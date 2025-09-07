use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::HEAP_BASE;
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn HeapAlloc(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let heap_handle = emu.reg_read(X86Register::RCX)?;
    let _flags = emu.reg_read(X86Register::RDX)?;
    let size = emu.reg_read(X86Register::R8)?;
    
    if heap_handle == HEAP_BASE {  // It's the process heap
        match HEAP_ALLOCATIONS.allocate(emu, size as usize) {
            Ok(addr) => {
                emu.reg_write(X86Register::RAX, addr)?;
                log::info!("[HeapAlloc] Allocated {} bytes at 0x{:x}", size, addr);
            }
            Err(e) => {
                log::error!("[HeapAlloc] Failed: {}", e);
                emu.reg_write(X86Register::RAX, 0)?;  // NULL on failure
            }
        }
    } else {
        log::error!("[HeapAlloc] Invalid heap handle: 0x{:x}", heap_handle);
        emu.reg_write(X86Register::RAX, 0)?;
    }
    
    Ok(())
}