use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::{emulation::memory::{TEB_BASE, TEB_TLS_SLOTS_OFFSET, TLS_MINIMUM_AVAILABLE}, winapi};

pub fn TlsSetValue(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
    // dwTlsIndex in RCX, lpTlsValue in RDX (x64 calling convention)
    
    // Get the TLS index from RCX
    let tls_index = emu.reg_read(X86Register::RCX)? as u32;
    // Get the value to store from RDX
    let value = emu.reg_read(X86Register::RDX)?;
    
    if tls_index >= TLS_MINIMUM_AVAILABLE as u32 {
        // Invalid index - return FALSE (0) and set last error
        emu.reg_write(X86Register::RAX, 0)?;
        
        // Set LastError to ERROR_INVALID_PARAMETER (87)
        winapi::set_last_error(emu, 87)?;
        
        log::warn!("kernel32!TlsSetValue({}, 0x{:016x}) -> FALSE (invalid index)", tls_index, value);
    } else {
        // Write the value to the TLS slot in TEB
        let slot_addr = TEB_BASE + TEB_TLS_SLOTS_OFFSET + (tls_index as u64 * 8);
        emu.mem_write(slot_addr, &value.to_le_bytes())?;
        
        // Return TRUE (1) for success
        emu.reg_write(X86Register::RAX, 1)?;
        
        // Clear LastError on success
        winapi::set_last_error(emu, 0)?;
        
        log::info!("kernel32!TlsSetValue({}, 0x{:016x}) -> TRUE", tls_index, value);
    }
    
    Ok(())
}