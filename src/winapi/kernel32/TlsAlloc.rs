use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::{Mutex, LazyLock};
use crate::emulation::memory::{TEB_BASE, TEB_TLS_SLOTS_OFFSET, TLS_MINIMUM_AVAILABLE, TLS_OUT_OF_INDEXES};

static TLS_ALLOCATION_BITMAP: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

pub fn TlsAlloc(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let mut bitmap = TLS_ALLOCATION_BITMAP.lock().unwrap();
    
    // Find first free slot (bit = 0 means free, bit = 1 means allocated)
    let mut index = None;
    for i in 0..TLS_MINIMUM_AVAILABLE {
        if (*bitmap & (1u64 << i)) == 0 {
            // Found a free slot
            *bitmap |= 1u64 << i;  // Mark as allocated
            index = Some(i);
            break;
        }
    }
    
    match index {
        Some(i) => {
            // Write 0 to the TLS slot in TEB
            let slot_addr = TEB_BASE + TEB_TLS_SLOTS_OFFSET + (i as u64 * 8);
            emu.mem_write(slot_addr, &0u64.to_le_bytes())?;
            
            // Return index in RAX
            emu.reg_write(X86Register::RAX, i as u64)?;
            
            log::info!("kernel32!TlsAlloc() -> {} (slot 0x{:016x})", i, slot_addr);
        }
        None => {
            // No free slots, return TLS_OUT_OF_INDEXES
            emu.reg_write(X86Register::RAX, TLS_OUT_OF_INDEXES as u64)?;

            // TODO: set last error?
            
            log::warn!("kernel32!TlsAlloc() -> TLS_OUT_OF_INDEXES (no free slots)");
        }
    }
    
    Ok(())
}