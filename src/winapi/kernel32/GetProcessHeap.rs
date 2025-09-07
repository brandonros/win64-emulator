use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory::HEAP_BASE;

pub fn GetProcessHeap(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // GetProcessHeap takes no parameters and returns a handle to the process heap
    
    // Use the HEAP_BASE as our process heap handle
    // This makes it consistent with the HeapManager's allocation base
    let heap_handle: u64 = HEAP_BASE;
    
    log::info!("[GetProcessHeap] Returning process heap handle: 0x{:x}", heap_handle);
    
    // Set the return value in RAX register
    emu.reg_write(X86Register::RAX, heap_handle)?;
    
    Ok(())
}