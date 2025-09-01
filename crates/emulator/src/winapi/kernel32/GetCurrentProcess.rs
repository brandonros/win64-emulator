use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetCurrentProcess(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // GetCurrentProcess takes no parameters and returns a pseudo handle
    // The pseudo handle is a special constant: (HANDLE)-1 = 0xFFFFFFFFFFFFFFFF
    
    let pseudo_handle: u64 = 0xFFFFFFFFFFFFFFFF; // (HANDLE)-1
    
    log::info!("[GetCurrentProcess] Returning pseudo handle: 0x{:x}", pseudo_handle);
    
    // Set the return value in RAX register
    emu.reg_write(RegisterX86::RAX, pseudo_handle)?;
    
    Ok(())
}
