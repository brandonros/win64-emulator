/*
// int* CDECL __p___argc(void) { return &MSVCRT___argc; }
}
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::OnceLock;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

// Store the argc pointer address once allocated
static ARGC_POINTER_ADDRESS: OnceLock<u64> = OnceLock::new();

pub fn __p___argc(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Check if already initialized
    let argc_addr = if let Some(&addr) = ARGC_POINTER_ADDRESS.get() {
        addr
    } else {
        // First call - allocate and initialize
        // Allocate space for argc (int = 4 bytes)
        let argc_addr = HEAP_ALLOCATIONS.allocate(emu, 4)
            .map_err(|e| {
                log::error!("[__p___argc] Failed to allocate argc: {}", e);
                EmulatorError::NOMEM
            })?;
        
        // Write argc value (1 = just program name)
        emu.mem_write(argc_addr, &1u32.to_le_bytes())?;
        
        log::info!("[__p___argc] Initialized argc at 0x{:x} with value 1", argc_addr);
        
        // Store for future calls
        ARGC_POINTER_ADDRESS.set(argc_addr).expect("Failed to set argc pointer address");
        
        argc_addr
    };
    
    log::debug!("[__p___argc] Returning argc pointer: 0x{:x}", argc_addr);
    
    // Return pointer in RAX
    emu.reg_write(X86Register::RAX, argc_addr)?;
    
    Ok(())
}