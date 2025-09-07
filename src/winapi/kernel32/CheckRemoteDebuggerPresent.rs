use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

/*
CheckRemoteDebuggerPresent function (debugapi.h)
02/22/2024
Determines whether the specified process is being debugged.

Syntax
C++

Copy
BOOL CheckRemoteDebuggerPresent(
  [in]      HANDLE hProcess,
  [in, out] PBOOL  pbDebuggerPresent
);
Parameters
[in] hProcess

A handle to the process.

[in, out] pbDebuggerPresent

A pointer to a variable that the function sets to TRUE if the specified process is being debugged, or FALSE otherwise.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.
*/

pub fn CheckRemoteDebuggerPresent(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL CheckRemoteDebuggerPresent(
    //   [in]      HANDLE hProcess,          // RCX
    //   [in, out] PBOOL  pbDebuggerPresent  // RDX
    // )
    
    let h_process = emu.reg_read(X86Register::RCX)?;
    let pb_debugger_present = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[CheckRemoteDebuggerPresent] hProcess: 0x{:x}", h_process);
    log::info!("[CheckRemoteDebuggerPresent] pbDebuggerPresent: 0x{:x}", pb_debugger_present);
    
    // Check for NULL output pointer
    if pb_debugger_present == 0 {
        log::error!("[CheckRemoteDebuggerPresent] NULL pbDebuggerPresent pointer");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Check for invalid process handle
    if h_process == 0 || h_process == 0xFFFFFFFFFFFFFFFF {
        log::error!("[CheckRemoteDebuggerPresent] Invalid process handle");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // For emulation purposes, we'll always report that no debugger is attached
    // This is the common case for most applications
    // In a real scenario, this would check the process's debug port or PEB flags
    let debugger_present: u32 = 0; // FALSE - no debugger attached
    
    // Write the result to the output parameter
    let debugger_present_bytes = debugger_present.to_le_bytes();
    match emu.mem_write(pb_debugger_present, &debugger_present_bytes) {
        Ok(_) => {
            log::info!("[CheckRemoteDebuggerPresent] Set *pbDebuggerPresent to {} (no debugger)", debugger_present);
        }
        Err(e) => {
            log::error!("[CheckRemoteDebuggerPresent] Failed to write to pbDebuggerPresent: {:?}", e);
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    
    // Special handling for GetCurrentProcess() pseudo-handle
    if h_process == 0xFFFFFFFFFFFFFFFF {
        log::info!("[CheckRemoteDebuggerPresent] Checking current process (pseudo-handle)");
    }
    
    log::info!("[CheckRemoteDebuggerPresent] Process is not being debugged");
    log::warn!("[CheckRemoteDebuggerPresent] Mock implementation - always returns no debugger");
    
    // Return TRUE (non-zero) to indicate success
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}