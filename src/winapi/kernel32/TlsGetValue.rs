use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::{TEB_BASE, TEB_TLS_SLOTS_OFFSET, TLS_MINIMUM_AVAILABLE};

pub fn TlsGetValue(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // LPVOID TlsGetValue(DWORD dwTlsIndex)
    // dwTlsIndex in RCX (x64 calling convention)
    
    // Get the TLS index from RCX
    let tls_index = emu.reg_read(RegisterX86::RCX)? as u32;
    
    if tls_index >= TLS_MINIMUM_AVAILABLE as u32 {
        // Invalid index - return NULL and set last error
        emu.reg_write(RegisterX86::RAX, 0)?;
        
        // Set LastError to ERROR_INVALID_PARAMETER (87)
        let error_addr = TEB_BASE + 0x68; // TEB_LAST_ERROR_VALUE_OFFSET
        emu.mem_write(error_addr, &87u32.to_le_bytes())?;
        
        log::warn!("kernel32!TlsGetValue({}) -> NULL (invalid index)", tls_index);
    } else {
        // Read the value from the TLS slot in TEB
        let slot_addr = TEB_BASE + TEB_TLS_SLOTS_OFFSET + (tls_index as u64 * 8);
        let mut value_bytes = [0u8; 8];
        emu.mem_read(slot_addr, &mut value_bytes)?;
        let value = u64::from_le_bytes(value_bytes);
        
        // Return the value in RAX
        emu.reg_write(RegisterX86::RAX, value)?;
        
        // Clear LastError on success
        let error_addr = TEB_BASE + 0x68;
        emu.mem_write(error_addr, &0u32.to_le_bytes())?;
        
        log::info!("kernel32!TlsGetValue({}) -> 0x{:016x}", tls_index, value);
    }
    
    Ok(())
}