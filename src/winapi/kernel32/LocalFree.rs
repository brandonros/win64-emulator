use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn LocalFree(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HLOCAL LocalFree(
    //   HLOCAL hMem  // RCX
    // )
    
    let mem_handle = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[LocalFree] hMem: 0x{:x}", mem_handle);
    
    // Check for NULL handle - succeeds and returns NULL
    if mem_handle == 0 {
        log::warn!("[LocalFree] Attempting to free NULL handle - returning NULL");
        emu.reg_write(X86Register::RAX, 0)?; // Return NULL (success)
        return Ok(());
    }
    
    // Free the memory using the heap manager
    match HEAP_ALLOCATIONS.free(mem_handle, emu) {
        Ok(()) => {
            log::info!("[LocalFree] Successfully freed memory at 0x{:x}", mem_handle);
            emu.reg_write(X86Register::RAX, 0)?; // Return NULL on success
        }
        Err(e) => {
            log::error!("[LocalFree] Failed to free memory at 0x{:x}: {}", mem_handle, e);
            // On failure, return the original handle
            emu.reg_write(X86Register::RAX, mem_handle)?;
        }
    }
    
    Ok(())
}