use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::System::Threading::CRITICAL_SECTION;

use crate::emulation::memory;

pub fn EnterCriticalSection(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to CRITICAL_SECTION structure from RCX register
    let critical_section_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[EnterCriticalSection] critical_section_ptr: 0x{:x}", critical_section_ptr);
    
    if critical_section_ptr > 0 {
        // Read the current CRITICAL_SECTION structure
        let mut cs: CRITICAL_SECTION = memory::read_struct(emu, critical_section_ptr)?;
        
        // For simple emulation, just mark it as locked
        // In real Windows, this would check ownership and handle recursion
        cs.LockCount = 0;  // 0 or positive indicates locked state
        cs.RecursionCount = 1;
        cs.OwningThread = 0x1000 as *mut _;  // Fake thread handle
        
        // Write back the updated structure
        memory::write_struct(emu, critical_section_ptr, &cs)?;
        
        log::info!("[EnterCriticalSection] Acquired lock at 0x{:x}", critical_section_ptr);
    }
    
    Ok(())
}
