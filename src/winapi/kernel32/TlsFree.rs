use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::{Mutex, LazyLock};
use crate::emulation::memory::{TEB_BASE, TEB_TLS_SLOTS_OFFSET, TLS_MINIMUM_AVAILABLE};
use crate::winapi;

static TLS_ALLOCATION_BITMAP: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

pub fn TlsFree(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL TlsFree(
    //   DWORD dwTlsIndex  // RCX
    // )
    
    let tls_index = emu.reg_read(X86Register::RCX)? as u32;
    
    log::info!("[TlsFree] dwTlsIndex: {}", tls_index);
    
    // Validate the index
    if tls_index >= TLS_MINIMUM_AVAILABLE as u32 {
        log::warn!("[TlsFree] Invalid TLS index: {} (max: {})", 
                  tls_index, TLS_MINIMUM_AVAILABLE - 1);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    let mut bitmap = TLS_ALLOCATION_BITMAP.lock().unwrap();
    
    // Check if the slot was actually allocated
    if (*bitmap & (1u64 << tls_index)) == 0 {
        log::warn!("[TlsFree] Attempting to free unallocated TLS index: {}", tls_index);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Free the slot by clearing the bit
    *bitmap &= !(1u64 << tls_index);
    
    // Clear the TLS slot value in TEB (set to 0)
    let slot_addr = TEB_BASE + TEB_TLS_SLOTS_OFFSET + (tls_index as u64 * 8);
    emu.mem_write(slot_addr, &0u64.to_le_bytes())?;
    
    log::info!("[TlsFree] Successfully freed TLS index {} (slot 0x{:016x})", 
              tls_index, slot_addr);
    
    // Return TRUE for success
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}