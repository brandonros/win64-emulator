use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn VirtualAlloc(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let address = emu.reg_read(X86Register::RCX)?;  // Desired address (usually NULL)
    let size = emu.reg_read(X86Register::RDX)?;     // Size to allocate
    let alloc_type = emu.reg_read(X86Register::R8)?; // MEM_COMMIT, MEM_RESERVE, etc.
    let protect = emu.reg_read(X86Register::R9)?;    // PAGE_READWRITE, PAGE_EXECUTE_READWRITE, etc.
    
    log::info!(
        "[VirtualAlloc] address: 0x{:x}, size: 0x{:x}, type: 0x{:x}, protect: 0x{:x}",
        address, size, alloc_type, protect
    );
    
    // For simplicity, ignore the address hint and protection flags
    // Just allocate memory using the heap manager
    match HEAP_ALLOCATIONS.allocate(emu, size as usize) {
        Ok(addr) => {
            emu.reg_write(X86Register::RAX, addr)?;
            log::info!("[VirtualAlloc] Allocated {} bytes at 0x{:x}", size, addr);
        }
        Err(e) => {
            log::error!("[VirtualAlloc] Failed: {}", e);
            emu.reg_write(X86Register::RAX, 0)?;  // NULL on failure
        }
    }
    
    Ok(())
}
