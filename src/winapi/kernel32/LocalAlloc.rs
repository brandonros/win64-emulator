use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn LocalAlloc(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)
    // uFlags in RCX, uBytes in RDX (x64 calling convention)
    
    let flags = emu.reg_read(X86Register::RCX)?;
    let size = emu.reg_read(X86Register::RDX)? as usize;
    
    if size == 0 {
        // Return NULL for zero size
        emu.reg_write(X86Register::RAX, 0)?;
        log::info!("kernel32!LocalAlloc(0x{:x}, 0) -> NULL", flags);
        return Ok(());
    }
    
    // Allocate memory
    let addr = match HEAP_ALLOCATIONS.allocate(emu, size) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("kernel32!LocalAlloc: {}", e);
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
    };

    // If LMEM_ZEROINIT flag is set (0x40), zero the memory
    if flags & 0x40 != 0 {
        let zeros = vec![0u8; size];
        emu.mem_write(addr, &zeros)?;
    }
    
    // Return allocated address in RAX
    emu.reg_write(X86Register::RAX, addr)?;
    
    log::info!("kernel32!LocalAlloc(0x{:x}, {}) -> 0x{:016x}", flags, size, addr);
    
    Ok(())
}