use unicorn_engine::{Unicorn, RegisterX86};

pub fn GetCurrentThread(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HANDLE GetCurrentThread(void)
    // Takes no parameters, returns a pseudo-handle to the current thread
    
    // In Windows, GetCurrentThread returns a pseudo-handle with the value -2 (0xFFFFFFFE)
    // This is a special constant that always refers to the current thread
    // It doesn't need to be closed with CloseHandle
    const CURRENT_THREAD_PSEUDO_HANDLE: u64 = 0xFFFFFFFFFFFFFFFE; // -2 as u64
    
    log::info!("[GetCurrentThread] Returning pseudo-handle: 0x{:x}", CURRENT_THREAD_PSEUDO_HANDLE);
    
    // Return the pseudo-handle in RAX
    emu.reg_write(RegisterX86::RAX, CURRENT_THREAD_PSEUDO_HANDLE)?;
    
    Ok(())
}