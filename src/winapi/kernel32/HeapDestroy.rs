use unicorn_engine::{Unicorn, RegisterX86};

pub fn HeapDestroy(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL HeapDestroy(
    //   HANDLE hHeap  // RCX
    // )
    
    let h_heap = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[HeapDestroy] hHeap: 0x{:x}", h_heap);
    
    // Check for NULL heap handle
    if h_heap == 0 {
        log::warn!("[HeapDestroy] NULL heap handle");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Check if trying to destroy the process heap
    // The process heap (returned by GetProcessHeap) cannot be destroyed
    const MOCK_PROCESS_HEAP_HANDLE: u64 = 0x100000;
    
    if h_heap == MOCK_PROCESS_HEAP_HANDLE {
        log::error!("[HeapDestroy] Cannot destroy the process heap!");
        log::info!("[HeapDestroy] Returning FALSE");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Check if this looks like one of our mock heap handles from HeapCreate
    if h_heap >= 0x110000 && h_heap < 0x200000 {
        log::info!("[HeapDestroy] Destroying mock heap handle: 0x{:x}", h_heap);
        
        // In a real implementation, this would:
        // - Free all memory blocks allocated from this heap
        // - Remove the heap from the process heap list
        // - Release all associated resources
        // - Invalidate the heap handle
        
        // For mock implementation, we just mark it as destroyed
        // We could maintain a list of valid heap handles if needed
        
        log::info!("[HeapDestroy] Mock: Heap destroyed successfully");
        log::warn!("[HeapDestroy] Mock implementation - not actually freeing memory");
        
        emu.reg_write(RegisterX86::RAX, 1)?; // Return TRUE - success
    } else {
        // Unknown or invalid heap handle
        log::warn!("[HeapDestroy] Invalid or unknown heap handle: 0x{:x} ERROR_INVALID_HANDLE", h_heap);
        
        // In Windows, HeapDestroy returns FALSE and sets last error to ERROR_INVALID_HANDLE
        // We'll set the last error
        const ERROR_INVALID_HANDLE: u32 = 6;
        crate::winapi::set_last_error(emu, ERROR_INVALID_HANDLE)?;
        
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
    }
    
    Ok(())
}