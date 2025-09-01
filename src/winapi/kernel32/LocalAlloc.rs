use unicorn_engine::{Unicorn, RegisterX86};

use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn LocalAlloc(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)
    // uFlags in RCX, uBytes in RDX (x64 calling convention)
    
    let flags = emu.reg_read(RegisterX86::RCX)?;
    let size = emu.reg_read(RegisterX86::RDX)? as usize;
    
    if size == 0 {
        // Return NULL for zero size
        emu.reg_write(RegisterX86::RAX, 0)?;
        log::info!("kernel32!LocalAlloc(0x{:x}, 0) -> NULL", flags);
        return Ok(());
    }
    
    // Allocate memory
    let mut heap = HEAP_ALLOCATIONS.lock().unwrap();
    let addr = match heap.allocate(emu, size) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("kernel32!LocalAlloc: {}", e);
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
    };

    // If LMEM_ZEROINIT flag is set (0x40), zero the memory
    if flags & 0x40 != 0 {
        let zeros = vec![0u8; size];
        emu.mem_write(addr, &zeros)?;
    }
    
    // Return allocated address in RAX
    emu.reg_write(RegisterX86::RAX, addr)?;
    
    log::info!("kernel32!LocalAlloc(0x{:x}, {}) -> 0x{:016x}", flags, size, addr);
    
    Ok(())
}