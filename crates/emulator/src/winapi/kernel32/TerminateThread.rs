use unicorn_engine::{Unicorn, RegisterX86};

pub fn TerminateThread(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL TerminateThread(
    //   HANDLE hThread,   // RCX
    //   DWORD  dwExitCode // RDX
    // )
    
    let thread_handle = emu.reg_read(RegisterX86::RCX)?;
    let exit_code = emu.reg_read(RegisterX86::RDX)? as u32;
    
    log::info!("[TerminateThread] hThread: 0x{:x}, dwExitCode: 0x{:x}", 
              thread_handle, exit_code);
    
    // Check for NULL or invalid handle
    if thread_handle == 0 || thread_handle == 0xFFFFFFFFFFFFFFFF {
        log::warn!("[TerminateThread] Invalid thread handle: 0x{:x}", thread_handle);
        // Return FALSE (0) to indicate failure
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Forcefully terminate the thread
    // - Set the thread's exit code
    // - Clean up thread resources
    // - This is generally considered dangerous and should be avoided
    
    log::warn!("[TerminateThread] Mock implementation - thread not actually terminated");
    log::warn!("[TerminateThread] Note: TerminateThread is dangerous in real code!");
    
    // Return TRUE (1) to indicate success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}