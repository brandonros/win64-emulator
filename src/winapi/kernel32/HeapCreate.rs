use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::HEAP_BASE;

pub fn HeapCreate(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let _flags = emu.reg_read(X86Register::RCX)?;
    let initial_size = emu.reg_read(X86Register::RDX)?;
    let maximum_size = emu.reg_read(X86Register::R8)?;
    
    log::info!(
        "[HeapCreate] flags: 0x{:x}, initial_size: 0x{:x}, max_size: 0x{:x}", 
        _flags, initial_size, maximum_size
    );
    
    // Just return HEAP_BASE - all heaps are the same in our emulation
    emu.reg_write(X86Register::RAX, HEAP_BASE)?;
    
    log::info!("[HeapCreate] Returning heap handle: 0x{:x}", HEAP_BASE);
    
    Ok(())
}