use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn VirtualFree(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let address = emu.reg_read(X86Register::RCX)?;
    let size = emu.reg_read(X86Register::RDX)?;     // Should be 0 for MEM_RELEASE
    let free_type = emu.reg_read(X86Register::R8)?; // MEM_RELEASE or MEM_DECOMMIT
    
    log::info!(
        "[VirtualFree] address: 0x{:x}, size: 0x{:x}, type: 0x{:x}",
        address, size, free_type
    );
    
    // For simplicity, just free the memory
    match HEAP_ALLOCATIONS.free(address, emu) {
        Ok(_) => {
            emu.reg_write(X86Register::RAX, 1)?;  // TRUE on success
            log::info!("[VirtualFree] Freed memory at 0x{:x}", address);
        }
        Err(e) => {
            log::error!("[VirtualFree] Failed: {}", e);
            emu.reg_write(X86Register::RAX, 0)?;  // FALSE on failure
        }
    }
    
    Ok(())
}