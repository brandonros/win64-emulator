use unicorn_engine::{Unicorn, RegisterX86};

pub fn Sleep(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void Sleep(
    //   DWORD dwMilliseconds  // RCX
    // )
    
    let milliseconds = emu.reg_read(RegisterX86::RCX)? as u32;
    
    log::info!("[Sleep] dwMilliseconds: {}", milliseconds);
    
    // Special case for Sleep(0) - yields remainder of time slice
    if milliseconds == 0 {
        log::info!("[Sleep] Sleep(0) - yielding time slice (mock)");
    } else if milliseconds == 0xFFFFFFFF {
        // INFINITE - sleep forever (shouldn't happen in normal execution)
        log::warn!("[Sleep] Sleep(INFINITE) called - mock implementation continuing");
    } else {
        log::info!("[Sleep] Sleeping for {} ms (mock - not actually sleeping)", milliseconds);
    }
    
    // In a real implementation, this would pause execution
    // For our mock, we just log and continue immediately
    // This is useful for emulation where we don't want actual delays
    
    // Sleep returns void, so no return value to set
    
    Ok(())
}