// PE module - handles parsing and loading PE64 executables

pub mod constants;
mod types;
mod loader;
mod imports;
mod exports;
mod utils;
mod relocations;
pub mod module_registry;

// Re-export the public API
pub use types::ImportedFunction;
pub use loader::LoadedPE;
pub use module_registry::MODULE_REGISTRY;

