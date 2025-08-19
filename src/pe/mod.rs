// PE module - handles parsing and loading PE64 executables

mod types;
mod loader;
mod imports;

// Re-export the public API
pub use types::ImportedFunction;
pub use loader::LoadedPE;

// Constants that will eventually move to emulation module
pub const MOCK_FUNCTION_BASE: u64 = 0x7F000000;
pub const MOCK_FUNCTION_SIZE: usize = 0x10000;