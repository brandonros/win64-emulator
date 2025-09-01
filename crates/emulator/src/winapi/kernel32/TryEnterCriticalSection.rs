use unicorn_engine::{Unicorn, RegisterX86};

pub fn TryEnterCriticalSection(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL TryEnterCriticalSection(
    //   LPCRITICAL_SECTION lpCriticalSection  // RCX
    // )
    
    let critical_section_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[TryEnterCriticalSection] lpCriticalSection: 0x{:x}", critical_section_ptr);
    
    // Check for NULL pointer
    if critical_section_ptr == 0 {
        log::warn!("[TryEnterCriticalSection] NULL critical section pointer provided");
        // Return FALSE (0) - failed to enter
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Attempt to enter the critical section without blocking
    // - If the critical section is available, enter it and return TRUE
    // - If the critical section is already owned by another thread, return FALSE immediately
    // - Unlike EnterCriticalSection, this never blocks/waits
    
    // For our mock implementation, we'll always succeed
    // In a single-threaded emulator, there's no contention
    let success = true;
    
    if success {
        log::info!("[TryEnterCriticalSection] Successfully entered critical section (mock)");
        log::warn!("[TryEnterCriticalSection] Mock implementation - no actual synchronization");
        // Return TRUE (1) - successfully entered
        emu.reg_write(RegisterX86::RAX, 1)?;
    } else {
        log::info!("[TryEnterCriticalSection] Critical section already owned, returning FALSE (mock)");
        // Return FALSE (0) - could not enter
        emu.reg_write(RegisterX86::RAX, 0)?;
    }
    
    Ok(())
}