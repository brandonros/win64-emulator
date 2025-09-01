use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetCurrentProcessId(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let pid = 1337u32;
    
    log::debug!("[GetCurrentProcessId] Returning process ID: {}", pid);
    
    // Windows GetCurrentProcessId returns DWORD (u32) in EAX
    emu.reg_write(RegisterX86::RAX, pid as u64)?;
    
    Ok(())
}
