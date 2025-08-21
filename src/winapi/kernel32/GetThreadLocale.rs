use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetThreadLocale(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Return US English locale (0x0409)
    // Format: 0x0409 = MAKELCID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
    let lcid = 0x0409u32;
    
    log::debug!("[GetThreadLocale] Returning locale: 0x{:04X} (en-US)", lcid);
    
    // Return value in EAX
    emu.reg_write(RegisterX86::RAX, lcid as u64)?;
    
    Ok(())
}