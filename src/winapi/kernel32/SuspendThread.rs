use unicorn_engine::{Unicorn, RegisterX86};

pub fn SuspendThread(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD SuspendThread(
    //   HANDLE hThread  // RCX
    // )
    
    let thread_handle = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[SuspendThread] hThread: 0x{:x}", thread_handle);
    
    // Check for NULL or invalid handle
    if thread_handle == 0 || thread_handle == 0xFFFFFFFFFFFFFFFF {
        log::warn!("[SuspendThread] Invalid thread handle: 0x{:x}", thread_handle);
        // Return -1 (0xFFFFFFFF) to indicate failure
        emu.reg_write(RegisterX86::RAX, 0xFFFFFFFF)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Suspend the specified thread
    // - Increment the thread's suspend count
    // - Return the previous suspend count
    
    // For our mock implementation, we'll return a fake suspend count
    // Typically 0 means the thread was running, 1 means it was already suspended once, etc.
    static mut MOCK_SUSPEND_COUNT: u32 = 0;
    
    let previous_count = unsafe {
        let prev = MOCK_SUSPEND_COUNT;
        MOCK_SUSPEND_COUNT += 1;
        prev
    };
    
    log::warn!("[SuspendThread] Mock implementation - thread not actually suspended");
    log::info!("[SuspendThread] Returning previous suspend count: {}", previous_count);
    
    // Return the previous suspend count
    emu.reg_write(RegisterX86::RAX, previous_count as u64)?;
    
    Ok(())
}