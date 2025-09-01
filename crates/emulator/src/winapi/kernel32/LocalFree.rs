use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn LocalFree(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HLOCAL LocalFree(
    //   HLOCAL hMem  // RCX
    // )
    
    let mem_handle = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[LocalFree] hMem: 0x{:x}", mem_handle);
    
    // Check for NULL handle - succeeds and returns NULL
    if mem_handle == 0 {
        log::warn!("[LocalFree] Attempting to free NULL handle - returning NULL");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL (success)
        return Ok(());
    }
    
    // Free the memory using the heap manager
    let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
    match heap_mgr.free(mem_handle) {
        Ok(()) => {
            log::info!("[LocalFree] Successfully freed memory at 0x{:x}", mem_handle);
            emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL on success
        }
        Err(e) => {
            log::error!("[LocalFree] Failed to free memory at 0x{:x}: {}", mem_handle, e);
            // On failure, return the original handle
            emu.reg_write(RegisterX86::RAX, mem_handle)?;
        }
    }
    
    Ok(())
}