use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use crate::emulation::memory::HEAP_BASE;

pub fn GetProcessHeap(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // GetProcessHeap takes no parameters and returns a handle to the process heap
    
    // Use the HEAP_BASE as our process heap handle
    // This makes it consistent with the HeapManager's allocation base
    let heap_handle: u64 = HEAP_BASE;
    
    log::info!("[GetProcessHeap] Returning process heap handle: 0x{:x}", heap_handle);
    
    // Set the return value in RAX register
    emu.reg_write(RegisterX86::RAX, heap_handle)?;
    
    Ok(())
}