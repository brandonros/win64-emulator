use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::HEAP_BASE;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn HeapFree(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL HeapFree(
    //   HANDLE hHeap,  // RCX
    //   DWORD dwFlags, // RDX
    //   LPVOID lpMem   // R8
    // )
    
    let heap_handle = emu.reg_read(X86Register::RCX)?;
    let flags = emu.reg_read(X86Register::RDX)?;
    let mem_ptr = emu.reg_read(X86Register::R8)?;
    
    log::info!("[HeapFree] hHeap: 0x{:x}, dwFlags: 0x{:x}, lpMem: 0x{:x}", 
              heap_handle, flags, mem_ptr);
    
    // Check for NULL pointer - succeeds but does nothing
    if mem_ptr == 0 {
        log::warn!("[HeapFree] Attempting to free NULL pointer - returning success");
        emu.reg_write(X86Register::RAX, 1)?; // Return TRUE
        return Ok(());
    }
    
    if heap_handle == HEAP_BASE {  // It's the process heap
        match HEAP_ALLOCATIONS.free(mem_ptr, emu) {
            Ok(()) => {
                log::info!("[HeapFree] Successfully freed memory at 0x{:x}", mem_ptr);
                emu.reg_write(X86Register::RAX, 1)?; // Return TRUE for success
            }
            Err(e) => {
                log::error!("[HeapFree] Failed to free memory at 0x{:x}: {}", mem_ptr, e);
                emu.reg_write(X86Register::RAX, 0)?; // Return FALSE for failure
            }
        }
    } else {
        log::error!("[HeapFree] Invalid heap handle: 0x{:x}", heap_handle);
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
    }
    
    Ok(())
}