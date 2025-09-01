use unicorn_engine::{RegisterX86, Unicorn};
use windows_sys::Win32::System::Threading::CRITICAL_SECTION;

use crate::emulation::memory;

pub fn LeaveCriticalSection(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to CRITICAL_SECTION structure from RCX register
    let critical_section_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[LeaveCriticalSection] critical_section_ptr: 0x{:x}", critical_section_ptr);
    
    if critical_section_ptr > 0 {
        // Read the current CRITICAL_SECTION structure
        let mut cs: CRITICAL_SECTION = memory::read_struct(emu, critical_section_ptr)?;
        
        // Reset to unlocked state
        cs.LockCount = -1;  // -1 indicates unlocked state
        cs.RecursionCount = 0;
        cs.OwningThread = std::ptr::null_mut();
        
        // Write back the updated structure
        memory::write_struct(emu, critical_section_ptr, &cs)?;
        
        log::info!("[LeaveCriticalSection] Released lock at 0x{:x}", critical_section_ptr);
    }
    
    Ok(())
}