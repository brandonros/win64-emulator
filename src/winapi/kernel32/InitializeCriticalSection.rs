use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::System::Threading::CRITICAL_SECTION;

use crate::winapi::structures;

pub fn InitializeCriticalSection(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to CRITICAL_SECTION structure from RCX register
    let critical_section_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[InitializeCriticalSection] critical_section_ptr: 0x{:x}", critical_section_ptr);
    
    if critical_section_ptr > 0 {
        let mock_critical_section = CRITICAL_SECTION {
            DebugInfo: std::ptr::null_mut(),
            LockCount: -1,  // -1 indicates unlocked state
            RecursionCount: 0,
            OwningThread: std::ptr::null_mut(),
            LockSemaphore: std::ptr::null_mut(),
            SpinCount: 0,
        };
        structures::write_struct(emu, critical_section_ptr, &mock_critical_section);
    }
    
    Ok(())
}