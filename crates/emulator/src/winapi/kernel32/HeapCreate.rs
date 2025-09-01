use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

use crate::emulation::memory::HEAP_BASE;

pub fn HeapCreate(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let _flags = emu.reg_read(RegisterX86::RCX)?;
    let initial_size = emu.reg_read(RegisterX86::RDX)?;
    let maximum_size = emu.reg_read(RegisterX86::R8)?;
    
    log::info!(
        "[HeapCreate] flags: 0x{:x}, initial_size: 0x{:x}, max_size: 0x{:x}", 
        _flags, initial_size, maximum_size
    );
    
    // Just return HEAP_BASE - all heaps are the same in our emulation
    emu.reg_write(RegisterX86::RAX, HEAP_BASE)?;
    
    log::info!("[HeapCreate] Returning heap handle: 0x{:x}", HEAP_BASE);
    
    Ok(())
}