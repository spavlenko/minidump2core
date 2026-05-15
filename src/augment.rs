//! Mapping augmentation: copies thread stacks and synthesized DSO link maps
//! into the page table so they can be emitted as `PT_LOAD` segments backed
//! by data captured in the minidump.

use std::collections::BTreeMap;

use crate::error::Md2CoreError;
use crate::model::{
    Architecture, CrashedProcess, DEFAULT_PAGE_SIZE, DsoDebug, Mapping, MappingPermissions,
    align_down, align_up, padded_vec,
};

/// Address of the synthetic page used to host the rebuilt link map. Matches
/// Breakpad's hard-coded value.
pub const LINK_MAP_ADDR: u64 = 4096;

/// Adds a captured byte blob to the mapping table, splitting mappings as needed.
///
/// # Errors
///
/// Returns an error if address arithmetic overflows or the mapping data is too large.
pub fn add_data_to_mapping(
    mappings: &mut BTreeMap<u64, Mapping>,
    data: &[u8],
    address: u64,
    page_size: u64,
) -> Result<(), Md2CoreError> {
    let aligned_address = align_down(address, page_size)?;
    let page_size_usize =
        usize::try_from(page_size).map_err(|_| Md2CoreError::IntegerOverflow("page size usize"))?;
    let prefix_len = usize::try_from(address - aligned_address)
        .map_err(|_| Md2CoreError::IntegerOverflow("mapping prefix length"))?;
    let mapping_data = padded_vec(prefix_len, data, page_size_usize)?;

    let containing_key = mappings
        .iter()
        .find_map(|(key, mapping)| mapping.contains(address).then_some(*key));

    if let Some(key) = containing_key {
        let mut data_mapping = mappings
            .get(&key)
            .cloned()
            .ok_or(Md2CoreError::MissingField("mapping"))?;

        if aligned_address != key
            && let Some(existing) = mappings.get_mut(&key)
        {
            existing.end_address = aligned_address;
            if data_mapping.filename.is_some() {
                data_mapping.offset = data_mapping
                    .offset
                    .checked_add(aligned_address - key)
                    .ok_or(Md2CoreError::IntegerOverflow("split mapping offset"))?;
            }
        }

        data_mapping.start_address = aligned_address;
        data_mapping.data = mapping_data;
        mappings.insert(data_mapping.start_address, data_mapping);
        return Ok(());
    }

    let data_len = u64::try_from(data.len())
        .map_err(|_| Md2CoreError::IntegerOverflow("mapping data length"))?;
    let end = align_up(
        address
            .checked_add(data_len)
            .ok_or(Md2CoreError::IntegerOverflow("synthetic mapping end"))?,
        page_size,
    )?;
    let mut mapping = Mapping::new(aligned_address, end, MappingPermissions::read_write())?;
    mapping.data = mapping_data;
    mappings.insert(mapping.start_address, mapping);
    Ok(())
}

/// Performs the full md2core augmentation pass:
///   * Inject each thread's stack bytes into the mapping table.
///   * Rebuild a `r_debug` + `link_map[]` blob at [`LINK_MAP_ADDR`].
///   * Patch the `DT_DEBUG` entry in the captured `_DYNAMIC` data to point at
///     the rebuilt link map and inject the patched data at its original VA.
///
/// # Errors
///
/// Returns an error if address arithmetic overflows or a mapping operation fails.
pub fn augment_process(process: &mut CrashedProcess, verbose: bool) -> Result<(), Md2CoreError> {
    let arch = process.architecture();

    // 1. Stack bytes
    let stacks: Vec<(u64, Vec<u8>)> = process
        .threads()
        .iter()
        .map(|t| (t.stack_address, t.stack.clone()))
        .collect();
    for (addr, stack) in &stacks {
        if !stack.is_empty() {
            if verbose {
                eprintln!(
                    "md2core: augment: injecting stack at {addr:#018x} ({} bytes)",
                    stack.len()
                );
            }
            add_data_to_mapping(process.mappings_mut(), stack, *addr, DEFAULT_PAGE_SIZE)?;
        }
    }

    // 2. Synthetic r_debug + link_map blob (only if we have any DSO data).
    let dso = process.dso_debug.clone();
    let signatures = process.signatures.clone();
    if dso.version != 0 || !dso.link_map.is_empty() || !dso.dynamic_data.is_empty() {
        let blob = build_link_map_blob(arch, &dso, &signatures)?;
        if verbose {
            eprintln!(
                "md2core: augment: link_map blob {} bytes at {LINK_MAP_ADDR:#018x}",
                blob.len(),
            );
        }
        add_data_to_mapping(
            process.mappings_mut(),
            &blob,
            LINK_MAP_ADDR,
            DEFAULT_PAGE_SIZE,
        )?;

        // 3. Patch and inject _DYNAMIC.
        if !dso.dynamic_data.is_empty() && dso.dynamic != 0 {
            let mut dyn_data = dso.dynamic_data.clone();
            patch_dt_debug(arch, &mut dyn_data, LINK_MAP_ADDR)?;
            if verbose {
                eprintln!(
                    "md2core: augment: patched _DYNAMIC ({} bytes) at {:#018x}",
                    dyn_data.len(),
                    dso.dynamic,
                );
            }
            add_data_to_mapping(
                process.mappings_mut(),
                &dyn_data,
                dso.dynamic,
                DEFAULT_PAGE_SIZE,
            )?;
        }
    } else if verbose {
        eprintln!("md2core: augment: no DSO debug info, skipping link_map");
    }

    if verbose {
        eprintln!(
            "md2core: augment: {} PT_LOAD segments after augmentation",
            process.mappings().len(),
        );
    }

    Ok(())
}

/// `DT_DEBUG` is the dynamic-section tag the loader fills with the address of
/// the live `r_debug` structure. Replacing it lets a debugger walk our
/// reconstructed link map.
const DT_NULL: u64 = 0;
const DT_DEBUG: u64 = 21;

/// Patches the first `DT_DEBUG` entry in `dynamic_data` in place so its
/// `d_un.d_ptr` field points at `link_map_addr`.
fn patch_dt_debug(
    arch: Architecture,
    dynamic_data: &mut [u8],
    link_map_addr: u64,
) -> Result<(), Md2CoreError> {
    let entry = if arch.is_64bit() { 16 } else { 8 };
    let mut offset = 0;
    while offset + entry <= dynamic_data.len() {
        let (tag, _) = read_word_pair(arch, &dynamic_data[offset..offset + entry]);
        if tag == DT_DEBUG {
            // d_un follows d_tag in memory.
            let value_off = offset + entry / 2;
            write_word(
                arch,
                &mut dynamic_data[value_off..value_off + entry / 2],
                link_map_addr,
            )?;
            return Ok(());
        }
        if tag == DT_NULL {
            return Ok(());
        }
        offset += entry;
    }
    Ok(())
}

fn read_word_pair(arch: Architecture, bytes: &[u8]) -> (u64, u64) {
    if arch.is_64bit() {
        let tag = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
        let value = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
        (tag, value)
    } else {
        let tag = u64::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap_or([0; 4])));
        let value = u64::from(u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4])));
        (tag, value)
    }
}

fn write_word(arch: Architecture, slot: &mut [u8], value: u64) -> Result<(), Md2CoreError> {
    if arch.is_64bit() {
        slot[..8].copy_from_slice(&value.to_le_bytes());
    } else {
        let value = u32::try_from(value)
            .map_err(|_| Md2CoreError::IntegerOverflow("32-bit dynamic word"))?;
        slot[..4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

/// Builds the `r_debug` + sequence of `link_map` records + name strings.
fn build_link_map_blob(
    arch: Architecture,
    dso: &DsoDebug,
    signatures: &std::collections::BTreeMap<u64, String>,
) -> Result<Vec<u8>, Md2CoreError> {
    let word = arch.long_size();
    let r_debug_size = if arch.is_64bit() { 40 } else { 20 };
    let link_map_size = 5 * word; // l_addr, l_name, l_ld, l_next, l_prev

    let mut data = Vec::new();

    // r_debug
    push_word(&mut data, u64::from(dso.version), word)?; // r_version (int but stored at long width for natural alignment on 64-bit)
    let r_map = if dso.link_map.is_empty() {
        0
    } else {
        LINK_MAP_ADDR + r_debug_size as u64
    };
    push_word(&mut data, r_map, word)?; // r_map
    push_word(&mut data, dso.brk, word)?; // r_brk
    push_word(&mut data, 0, word)?; // r_state = RT_CONSISTENT (stored at long width)
    push_word(&mut data, dso.ldbase, word)?; // r_ldbase
    debug_assert_eq!(data.len(), r_debug_size);

    // link_map records, with their name strings appended after each record.
    for (i, entry) in dso.link_map.iter().enumerate() {
        let filename = signatures
            .get(&entry.addr)
            .cloned()
            .unwrap_or_else(|| entry.name.clone());
        let name_offset = LINK_MAP_ADDR + data.len() as u64 + link_map_size as u64;
        let prev = if i == 0 {
            0
        } else {
            // Address of the previous link_map record.
            // We compute it as: LINK_MAP_ADDR + (current data offset - previous record size).
            // Tracked via a running address below for clarity.
            link_map_record_addr(
                LINK_MAP_ADDR,
                &data,
                link_map_size,
                filename_padded_size(&dso.link_map[i - 1].name_for(signatures)),
            )
        };
        let next = if i + 1 == dso.link_map.len() {
            0
        } else {
            // Next record starts after current (link_map_size + padded_name_size).
            LINK_MAP_ADDR
                + data.len() as u64
                + link_map_size as u64
                + filename_padded_size(&filename)
        };

        push_word(&mut data, entry.addr, word)?; // l_addr
        push_word(&mut data, name_offset, word)?; // l_name (pointer into our blob)
        push_word(&mut data, entry.ld, word)?; // l_ld
        push_word(&mut data, next, word)?; // l_next
        push_word(&mut data, prev, word)?; // l_prev

        let name_bytes = filename.as_bytes();
        data.extend_from_slice(name_bytes);
        // pad to 8 bytes inclusive of NUL (matches C++ "8 - (size & 7)").
        let pad = 8 - (name_bytes.len() & 7);
        data.resize(data.len() + pad, 0);
    }

    Ok(data)
}

/// Computes the address of a `link_map` record placed just before the current
/// data tail, given the size of the previous filename block.
fn link_map_record_addr(
    base: u64,
    current_data: &[u8],
    link_map_size: usize,
    prev_name_block: u64,
) -> u64 {
    // current_data already contains: [r_debug][... prior records and names ...]
    // The previous record's address = base + current_data.len() - prev_name_block - link_map_size.
    base + current_data.len() as u64 - prev_name_block - link_map_size as u64
}

fn filename_padded_size(s: &str) -> u64 {
    let n = s.len();
    let pad = 8 - (n & 7);
    (n + pad) as u64
}

trait LinkNameLookup {
    fn name_for(&self, signatures: &std::collections::BTreeMap<u64, String>) -> String;
}

impl LinkNameLookup for crate::model::LinkMapEntry {
    fn name_for(&self, signatures: &std::collections::BTreeMap<u64, String>) -> String {
        signatures
            .get(&self.addr)
            .cloned()
            .unwrap_or_else(|| self.name.clone())
    }
}

fn push_word(out: &mut Vec<u8>, value: u64, word: usize) -> Result<(), Md2CoreError> {
    if word == 8 {
        out.extend_from_slice(&value.to_le_bytes());
    } else {
        let value = u32::try_from(value)
            .map_err(|_| Md2CoreError::IntegerOverflow("32-bit link-map word"))?;
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}
