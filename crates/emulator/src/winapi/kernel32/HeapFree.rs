use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::HEAP_BASE;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn HeapFree(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL HeapFree(
    //   HANDLE hHeap,  // RCX
    //   DWORD dwFlags, // RDX
    //   LPVOID lpMem   // R8
    // )
    
    let heap_handle = emu.reg_read(RegisterX86::RCX)?;
    let flags = emu.reg_read(RegisterX86::RDX)?;
    let mem_ptr = emu.reg_read(RegisterX86::R8)?;
    
    log::info!("[HeapFree] hHeap: 0x{:x}, dwFlags: 0x{:x}, lpMem: 0x{:x}", 
              heap_handle, flags, mem_ptr);
    
    // Check for NULL pointer - succeeds but does nothing
    if mem_ptr == 0 {
        log::warn!("[HeapFree] Attempting to free NULL pointer - returning success");
        emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE
        return Ok(());
    }
    
    if heap_handle == HEAP_BASE {  // It's the process heap
        let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
        match heap_mgr.free(mem_ptr) {
            Ok(()) => {
                log::info!("[HeapFree] Successfully freed memory at 0x{:x}", mem_ptr);
                emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE for success
            }
            Err(e) => {
                log::error!("[HeapFree] Failed to free memory at 0x{:x}: {}", mem_ptr, e);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE for failure
            }
        }
    } else {
        log::error!("[HeapFree] Invalid heap handle: 0x{:x}", heap_handle);
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
    }
    
    Ok(())
}