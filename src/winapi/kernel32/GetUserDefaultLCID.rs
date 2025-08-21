use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetUserDefaultLCID(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Return US English locale (0x0409)
    // Format: 0x0409 = MAKELCID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
    let lcid = 0x0409u32;
    
    log::debug!("[GetUserDefaultLCID] Returning LCID: 0x{:04x}", lcid);
    
    // Return LCID in EAX
    emu.reg_write(RegisterX86::EAX, lcid as u64)?;
    
    Ok(())
}
