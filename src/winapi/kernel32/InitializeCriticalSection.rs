use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use windows_sys::Win32::System::Threading::CRITICAL_SECTION;

pub fn InitializeCriticalSection(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get the pointer to CRITICAL_SECTION structure from RCX register
    let critical_section_ptr = emu.reg_read(X86Register::RCX)?;
    
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
        memory::write_struct(emu, critical_section_ptr, &mock_critical_section)?;
    }
    
    Ok(())
}