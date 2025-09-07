use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::{emulation::memory::{TEB_BASE, TEB_TLS_SLOTS_OFFSET, TLS_MINIMUM_AVAILABLE}, winapi};

pub fn TlsGetValue(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // LPVOID TlsGetValue(DWORD dwTlsIndex)
    // dwTlsIndex in RCX (x64 calling convention)
    
    // Get the TLS index from RCX
    let tls_index = emu.reg_read(X86Register::RCX)? as u32;
    
    if tls_index >= TLS_MINIMUM_AVAILABLE as u32 {
        // Invalid index - return NULL and set last error
        emu.reg_write(X86Register::RAX, 0)?;
        
        // Set LastError to ERROR_INVALID_PARAMETER (87)
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        
        log::warn!("kernel32!TlsGetValue({}) -> NULL (invalid index)", tls_index);
    } else {
        // Read the value from the TLS slot in TEB
        let slot_addr = TEB_BASE + TEB_TLS_SLOTS_OFFSET + (tls_index as u64 * 8);
        let mut value_bytes = [0u8; 8];
        emu.mem_read(slot_addr, &mut value_bytes)?;
        let value = u64::from_le_bytes(value_bytes);
        
        // Return the value in RAX
        emu.reg_write(X86Register::RAX, value)?;
        
        // Clear LastError on success
        winapi::set_last_error(emu, 0)?;
        
        log::info!("kernel32!TlsGetValue({}) -> 0x{:016x}", tls_index, value);
    }
    
    Ok(())
}