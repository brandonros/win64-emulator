use unicorn_engine::{uc_error, Permission, Unicorn};
use crate::pe::LoadedPE;

pub mod constants;
pub mod utils;
pub mod teb;
pub mod peb;
pub mod heap_manager;

pub use constants::*;
pub use utils::*;
pub use teb::setup_teb;
pub use peb::setup_peb;

pub fn setup_memory(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n🗺️  Setting up memory layout:");
    
    // Set up stack
    emu.mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)?;
    log::info!("  Stack: 0x{:016x} - 0x{:016x}", STACK_BASE, STACK_BASE + STACK_SIZE as u64);
    
    // Set up heap (basic)
    emu.mem_map(HEAP_BASE, HEAP_SIZE, Permission::READ | Permission::WRITE | Permission::EXEC)?; // adding EXEC for VirtualAlloc
    log::info!("  Heap: 0x{:016x} - 0x{:016x}", HEAP_BASE, HEAP_BASE + HEAP_SIZE as u64);

    // TODO: setup_teb peb loader
    
    Ok(())
}