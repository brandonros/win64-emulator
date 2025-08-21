use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn SetThreadLocale(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the new locale from RCX register
    let new_locale = emu.reg_read(RegisterX86::ECX)? as u32;
    
    log::debug!("[SetThreadLocale] Setting thread locale to: 0x{:04x}", new_locale);
    
    // In a real implementation, we'd store the old locale and update the current one
    // For mocking, we'll just return success with a fake "previous" locale
    let previous_locale = 0x0409u32; // Return US English as the "previous" locale
    
    log::debug!("[SetThreadLocale] Returning previous locale: 0x{:04x}", previous_locale);
    
    // Return the previous LCID in EAX (even though docs say BOOL, it actually returns LCID)
    emu.reg_write(RegisterX86::EAX, previous_locale as u64)?;
    
    Ok(())
}
