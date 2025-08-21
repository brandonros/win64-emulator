use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use crate::emulation::memory::HEAP_BASE;
use crate::winapi::heap_manager::HEAP_ALLOCATIONS;

pub fn HeapAlloc(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let heap_handle = emu.reg_read(RegisterX86::RCX)?;
    let _flags = emu.reg_read(RegisterX86::RDX)?;
    let size = emu.reg_read(RegisterX86::R8)?;
    
    if heap_handle == HEAP_BASE {  // It's the process heap
        let mut heap_mgr = HEAP_ALLOCATIONS.lock().unwrap();
        match heap_mgr.allocate(size as usize) {
            Ok(addr) => {
                emu.reg_write(RegisterX86::RAX, addr)?;
                log::info!("[HeapAlloc] Allocated {} bytes at 0x{:x}", size, addr);
            }
            Err(e) => {
                log::error!("[HeapAlloc] Failed: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?;  // NULL on failure
            }
        }
    } else {
        log::error!("[HeapAlloc] Invalid heap handle: 0x{:x}", heap_handle);
        emu.reg_write(RegisterX86::RAX, 0)?;
    }
    
    Ok(())
}