use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn IsDebuggerPresent(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL IsDebuggerPresent(void)
    // Takes no parameters, returns TRUE if a debugger is attached, FALSE otherwise
    
    // In a real implementation, this would check the PEB (Process Environment Block)
    // specifically the BeingDebugged flag at PEB+0x02
    
    // For our mock implementation, we'll always return FALSE (no debugger)
    // This is common for anti-debugging bypass in emulation
    let debugger_present = false;
    
    log::info!("[IsDebuggerPresent] Returning: {} (no debugger)", debugger_present);
    
    // Some malware uses this as an anti-debugging technique
    log::warn!("[IsDebuggerPresent] Note: This is often used as an anti-debugging check");
    
    // Return FALSE (0) - no debugger present
    emu.reg_write(X86Register::RAX, if debugger_present { 1 } else { 0 })?;
    
    Ok(())
}