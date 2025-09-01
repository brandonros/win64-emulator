use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

pub fn VirtualFree(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let address = emu.reg_read(RegisterX86::RCX)?;
    let size = emu.reg_read(RegisterX86::RDX)?;     // Should be 0 for MEM_RELEASE
    let free_type = emu.reg_read(RegisterX86::R8)?; // MEM_RELEASE or MEM_DECOMMIT
    
    log::info!(
        "[VirtualFree] address: 0x{:x}, size: 0x{:x}, type: 0x{:x}",
        address, size, free_type
    );
    
    // For simplicity, just free the memory
    let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
    match heap_mgr.free(address, emu) {
        Ok(_) => {
            emu.reg_write(RegisterX86::RAX, 1)?;  // TRUE on success
            log::info!("[VirtualFree] Freed memory at 0x{:x}", address);
        }
        Err(e) => {
            log::error!("[VirtualFree] Failed: {}", e);
            emu.reg_write(RegisterX86::RAX, 0)?;  // FALSE on failure
        }
    }
    
    Ok(())
}