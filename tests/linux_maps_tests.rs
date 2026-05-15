use md2core::Md2CoreError;
use md2core::linux_maps::{looks_like_linux_maps, parse_linux_maps};

#[test]
fn parses_absolute_file_mappings_and_permissions() {
    let input = b"00400000-00452000 r-xp 00000000 08:02 173521 /bin/cat\n\
                  00e1b000-00e3c000 rw-p 00000000 00:00 0 [heap]\n";

    let mappings = parse_linux_maps(input).unwrap_or_else(|err| panic!("{err}"));

    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].start_address, 0x0040_0000);
    assert_eq!(mappings[0].end_address, 0x0045_2000);
    assert_eq!(mappings[0].offset, 0);
    assert!(mappings[0].permissions.is_readable());
    assert!(!mappings[0].permissions.is_writable());
    assert!(mappings[0].permissions.is_executable());
    assert_eq!(mappings[0].filename.as_deref(), Some("/bin/cat"));
}

#[test]
fn detects_linux_maps_masquerading_as_auxv() {
    assert!(looks_like_linux_maps(
        b"00400000-00452000 r-xp 00000000 08:02 173521 /bin/cat"
    ));
    assert!(!looks_like_linux_maps(&[0, 1, 2, 3, 4, 5]));
}

// --- Group 6: looks_like_linux_maps boundary cases ---

/// A buffer of exactly 17 bytes returns false (the check requires `data.len() > 17`).
#[test]
fn looks_like_linux_maps_exactly_17_bytes_is_false() {
    // 17 bytes of valid hex/dash characters: "00400000-00452000" is 17 bytes.
    let buf = b"00400000-00452000";
    assert_eq!(buf.len(), 17);
    assert!(!looks_like_linux_maps(buf));
}

/// A buffer of exactly 18 bytes with valid hex content returns true.
#[test]
fn looks_like_linux_maps_exactly_18_bytes_is_true() {
    // 18 bytes: "00400000-004520001" — all hex/dash characters.
    let buf = b"00400000-004520001";
    assert_eq!(buf.len(), 18);
    assert!(looks_like_linux_maps(buf));
}

/// A non-hex character at position 10 makes the function return false.
#[test]
fn looks_like_linux_maps_non_hex_at_position_10() {
    // First 10 bytes are valid hex/dash, position 10 is 'Z'.
    let buf = b"00400000-0Z452000 r-xp 00000000 08:02 173521 /bin/cat";
    assert!(!looks_like_linux_maps(buf));
}

// --- Group 7: linux_maps parsing edge cases ---

/// Lines with `[heap]` as the filename should be excluded.
#[test]
fn parse_maps_excludes_heap_mapping() {
    let input = b"00e1b000-00e3c000 rw-p 00000000 00:00 0 [heap]\n";
    let mappings = parse_linux_maps(input).unwrap();
    assert!(mappings.is_empty(), "[heap] mapping should be excluded");
}

/// Lines with `[stack]` as the filename should be excluded.
#[test]
fn parse_maps_excludes_stack_mapping() {
    let input = b"7fff0000-7fff2000 rw-p 00000000 00:00 0 [stack]\n";
    let mappings = parse_linux_maps(input).unwrap();
    assert!(mappings.is_empty(), "[stack] mapping should be excluded");
}

/// Lines with no filename field should be excluded.
#[test]
fn parse_maps_excludes_empty_filename() {
    // Five fields, no sixth (filename) field.
    let input = b"7f001000-7f002000 rw-p 00000000 00:00 0\n";
    let mappings = parse_linux_maps(input).unwrap();
    assert!(
        mappings.is_empty(),
        "mapping without filename should be excluded"
    );
}

/// Lines with `/path/foo.so (deleted)` should be included because the filename starts with `/`.
/// Note: `parse_linux_maps` uses whitespace-split parsing, so only the first token
/// of the path field is captured — `/lib/foo.so`, not `/lib/foo.so (deleted)`.
#[test]
fn parse_maps_includes_deleted_files() {
    let input = b"7f001000-7f002000 r-xp 00000000 08:02 1234 /lib/foo.so (deleted)\n";
    let mappings = parse_linux_maps(input).unwrap();
    assert_eq!(
        mappings.len(),
        1,
        "mapping with /path (deleted) should be included"
    );
    // The parser takes only the first whitespace token as the filename.
    assert_eq!(mappings[0].filename.as_deref(), Some("/lib/foo.so"));
}

/// A line with a non-zero file offset should parse and preserve that offset.
#[test]
fn parse_maps_handles_nonzero_offset() {
    let input = b"7f001000-7f002000 r--p 00020000 08:02 1234 /lib/foo.so\n";
    let mappings = parse_linux_maps(input).unwrap();
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].offset, 0x0002_0000);
    assert_eq!(mappings[0].start_address, 0x7f00_1000);
    assert_eq!(mappings[0].end_address, 0x7f00_2000);
}

/// A malformed line (missing the range field entirely) should return an error.
#[test]
fn parse_maps_rejects_malformed_line() {
    // Empty line would just be skipped (no parts.next()), but a line with only
    // a partial range (no '-' separator for end address) causes parse failure.
    let input = b"nothex r-xp 00000000 08:02 1234 /bin/foo\n";
    let result = parse_linux_maps(input);
    assert!(
        matches!(result, Err(Md2CoreError::InvalidMapsLine(_))),
        "malformed line should return InvalidMapsLine error, got: {result:?}"
    );
}
