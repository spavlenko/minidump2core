use crate::error::Md2CoreError;
use crate::model::{Mapping, MappingPermissions};

/// Returns true when a byte stream looks like `/proc/<pid>/maps` text.
#[must_use]
pub fn looks_like_linux_maps(data: &[u8]) -> bool {
    if data.len() <= 17 {
        return false;
    }
    data[..17]
        .iter()
        .all(|byte| byte.is_ascii_hexdigit() || *byte == b'-')
}

/// Parses the subset of Linux maps lines used by Breakpad md2core.
///
/// # Errors
///
/// Returns an error if the data is not valid UTF-8 or if a maps line cannot be parsed.
pub fn parse_linux_maps(data: &[u8]) -> Result<Vec<Mapping>, Md2CoreError> {
    let text = std::str::from_utf8(data).map_err(|_| Md2CoreError::InvalidUtf8 {
        stream: "MD_LINUX_MAPS",
    })?;
    let mut mappings = Vec::new();

    for line in text.lines() {
        if let Some(mapping) = parse_maps_line(line)? {
            mappings.push(mapping);
        }
    }

    Ok(mappings)
}

fn parse_maps_line(line: &str) -> Result<Option<Mapping>, Md2CoreError> {
    let mut parts = line.split_whitespace();
    let range = parts
        .next()
        .ok_or_else(|| Md2CoreError::InvalidMapsLine(line.to_owned()))?;
    let permissions = parts
        .next()
        .ok_or_else(|| Md2CoreError::InvalidMapsLine(line.to_owned()))?;
    let offset = parts
        .next()
        .ok_or_else(|| Md2CoreError::InvalidMapsLine(line.to_owned()))?;

    let mut range_parts = range.splitn(2, '-');
    let start = parse_hex_u64(range_parts.next(), line)?;
    let end = parse_hex_u64(range_parts.next(), line)?;
    let file_offset = u64::from_str_radix(offset, 16)
        .map_err(|_| Md2CoreError::InvalidMapsLine(line.to_owned()))?;

    let filename = parts.nth(2);
    let Some(filename) = filename else {
        return Ok(None);
    };
    if !filename.starts_with('/') {
        return Ok(None);
    }

    let permissions = MappingPermissions::new(
        permissions.contains('r'),
        permissions.contains('w'),
        permissions.contains('x'),
    );
    Ok(Some(
        Mapping::new(start, end, permissions)?.with_file(filename.to_owned(), file_offset),
    ))
}

fn parse_hex_u64(value: Option<&str>, line: &str) -> Result<u64, Md2CoreError> {
    let value = value.ok_or_else(|| Md2CoreError::InvalidMapsLine(line.to_owned()))?;
    u64::from_str_radix(value, 16).map_err(|_| Md2CoreError::InvalidMapsLine(line.to_owned()))
}
