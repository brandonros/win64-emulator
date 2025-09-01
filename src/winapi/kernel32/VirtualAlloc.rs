use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn VirtualAlloc(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let address = emu.reg_read(RegisterX86::RCX)?;  // Desired address (usually NULL)
    let size = emu.reg_read(RegisterX86::RDX)?;     // Size to allocate
    let alloc_type = emu.reg_read(RegisterX86::R8)?; // MEM_COMMIT, MEM_RESERVE, etc.
    let protect = emu.reg_read(RegisterX86::R9)?;    // PAGE_READWRITE, PAGE_EXECUTE_READWRITE, etc.
    
    log::info!(
        "[VirtualAlloc] address: 0x{:x}, size: 0x{:x}, type: 0x{:x}, protect: 0x{:x}",
        address, size, alloc_type, protect
    );
    
    // For simplicity, ignore the address hint and protection flags
    // Just allocate memory using the heap manager
    let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
    match heap_mgr.allocate(emu, size as usize) {
        Ok(addr) => {
            emu.reg_write(RegisterX86::RAX, addr)?;
            log::info!("[VirtualAlloc] Allocated {} bytes at 0x{:x}", size, addr);
        }
        Err(e) => {
            log::error!("[VirtualAlloc] Failed: {}", e);
            emu.reg_write(RegisterX86::RAX, 0)?;  // NULL on failure
        }
    }
    
    Ok(())
}
