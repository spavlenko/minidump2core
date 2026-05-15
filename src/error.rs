use thiserror::Error;

/// Error type used by the safe md2core conversion pipeline.
#[derive(Debug, Error)]
pub enum Md2CoreError {
    /// A requested byte range is outside of the backing buffer.
    #[error("range {offset}..{end} is outside the buffer of length {len}")]
    RangeOutOfBounds {
        /// Requested start offset.
        offset: usize,
        /// Requested exclusive end offset.
        end: usize,
        /// Backing buffer length.
        len: usize,
    },

    /// Integer arithmetic overflowed while computing an address or size.
    #[error("integer overflow while computing {0}")]
    IntegerOverflow(&'static str),

    /// A memory mapping has an invalid address interval.
    #[error("invalid mapping range: start {start:#x}, end {end:#x}")]
    InvalidAddressRange {
        /// Inclusive start virtual address.
        start: u64,
        /// Exclusive end virtual address.
        end: u64,
    },

    /// A page or note alignment value is invalid.
    #[error("alignment must be non-zero")]
    InvalidAlignment,

    /// A text stream was not valid UTF-8.
    #[error("{stream} stream is not valid UTF-8")]
    InvalidUtf8 {
        /// Stream name.
        stream: &'static str,
    },

    /// A Linux maps line could not be parsed.
    #[error("failed to parse linux maps line: {0}")]
    InvalidMapsLine(String),

    /// A required field or stream has not been provided.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A state transition was requested before its prerequisites were met.
    #[error("invalid state transition: {0}")]
    InvalidState(&'static str),

    /// The input minidump could not be read or a typed stream failed to parse.
    #[error("minidump read error: {0}")]
    MinidumpRead(#[from] minidump::Error),

    /// The minidump was not produced on a supported Linux-like system.
    #[error("unsupported minidump system: os={os}, cpu={cpu}")]
    UnsupportedSystem {
        /// Operating system reported by rust-minidump.
        os: String,
        /// CPU architecture reported by rust-minidump.
        cpu: String,
    },

    /// A CPU context did not match the architecture reported by system info.
    #[error("CPU context mismatch: expected {expected}, found {found}")]
    ContextMismatch {
        /// Architecture from system info.
        expected: &'static str,
        /// Architecture inferred from the thread context.
        found: &'static str,
    },

    /// I/O error writing the output core file.
    #[error("I/O error writing core file: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error from the `scroll` byte writer.
    #[error("byte serialization error: {0}")]
    Serialize(String),
}

impl From<scroll::Error> for Md2CoreError {
    fn from(err: scroll::Error) -> Self {
        Md2CoreError::Serialize(err.to_string())
    }
}

impl PartialEq for Md2CoreError {
    /// Equality is implemented via `Debug` so tests can compare errors even
    /// when the wrapped source types do not themselves implement `Eq`
    /// (`std::io::Error`, `minidump::Error`).
    fn eq(&self, other: &Self) -> bool {
        format!("{self:?}") == format!("{other:?}")
    }
}

impl Eq for Md2CoreError {}
