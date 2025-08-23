use unicorn_engine::{Unicorn, RegisterX86};

pub fn ResumeThread(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD ResumeThread(
    //   HANDLE hThread  // RCX
    // )
    
    let thread_handle = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[ResumeThread] hThread: 0x{:x}", thread_handle);
    
    // Check for NULL or invalid handle
    if thread_handle == 0 || thread_handle == 0xFFFFFFFFFFFFFFFF {
        log::warn!("[ResumeThread] Invalid thread handle: 0x{:x}", thread_handle);
        // Return -1 (0xFFFFFFFF) to indicate failure
        emu.reg_write(RegisterX86::RAX, 0xFFFFFFFF)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Resume the specified thread
    // - Decrement the thread's suspend count
    // - Return the previous suspend count
    
    // For our mock implementation, we'll return a fake suspend count
    // This should pair with SuspendThread's mock counter
    static mut MOCK_SUSPEND_COUNT: u32 = 0;
    
    let previous_count = unsafe {
        let prev = MOCK_SUSPEND_COUNT;
        if MOCK_SUSPEND_COUNT > 0 {
            MOCK_SUSPEND_COUNT -= 1;
            prev
        } else {
            // Thread wasn't suspended
            0
        }
    };
    
    log::warn!("[ResumeThread] Mock implementation - thread not actually resumed");
    log::info!("[ResumeThread] Returning previous suspend count: {}", previous_count);
    
    // Return the previous suspend count
    emu.reg_write(RegisterX86::RAX, previous_count as u64)?;
    
    Ok(())
}