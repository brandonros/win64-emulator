use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn WaitForSingleObject(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // DWORD WaitForSingleObject(
    //   HANDLE hHandle,        // RCX
    //   DWORD  dwMilliseconds  // RDX
    // )
    
    let handle = emu.reg_read(X86Register::RCX)?;
    let timeout_ms = emu.reg_read(X86Register::RDX)? as u32;
    
    log::info!("[WaitForSingleObject] hHandle: 0x{:x}, dwMilliseconds: {}", 
              handle, timeout_ms);
    
    // Check for NULL or invalid handle
    if handle == 0 || handle == 0xFFFFFFFFFFFFFFFF {
        log::warn!("[WaitForSingleObject] Invalid handle: 0x{:x}", handle);
        // Return WAIT_FAILED
        const WAIT_FAILED: u32 = 0xFFFFFFFF;
        emu.reg_write(X86Register::RAX, WAIT_FAILED as u64)?;
        return Ok(());
    }
    
    // Define return codes
    const WAIT_OBJECT_0: u32 = 0x00000000;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const WAIT_ABANDONED: u32 = 0x00000080;
    const INFINITE: u32 = 0xFFFFFFFF;
    
    // Mock implementation logic
    let result = if timeout_ms == 0 {
        // Immediate return, check if object is signaled
        // For mock, we'll say it's not signaled
        log::info!("[WaitForSingleObject] Zero timeout - returning WAIT_TIMEOUT");
        WAIT_TIMEOUT
    } else if timeout_ms == INFINITE {
        // Wait forever - for mock, we'll pretend it succeeded immediately
        log::warn!("[WaitForSingleObject] INFINITE wait requested - mock returning immediately");
        WAIT_OBJECT_0
    } else {
        // Normal timeout - for mock, we'll pretend it succeeded
        log::info!("[WaitForSingleObject] Waiting {} ms (mock - returning immediately)", timeout_ms);
        WAIT_OBJECT_0
    };
    
    log::info!("[WaitForSingleObject] Returning: 0x{:x}", result);
    
    // Return the result
    emu.reg_write(X86Register::RAX, result as u64)?;
    
    Ok(())
}