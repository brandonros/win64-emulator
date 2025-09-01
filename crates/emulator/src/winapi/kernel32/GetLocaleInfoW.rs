use unicorn_engine::{Unicorn, RegisterX86};

use crate::{emulation::memory, winapi::{self, locale}};

pub fn GetLocaleInfoW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers
    let locale = emu.reg_read(RegisterX86::RCX)? as u32;
    let lctype = emu.reg_read(RegisterX86::RDX)? as u32;
    let lp_lc_data = emu.reg_read(RegisterX86::R8)?;
    let cch_data = emu.reg_read(RegisterX86::R9)? as u32;

    log::debug!("[GetLocaleInfoW] locale: 0x{:x} lctype: 0x{:x} buffer: 0x{:x} size: {}",
        locale, lctype, lp_lc_data, cch_data);

    // Get the locale string based on type
    let result = locale::get_locale_mock(lctype);

    // Calculate required size in characters (including null terminator)
    let required_size = (result.len() + 1) as u32;

    // If cch_data is 0, return required buffer size
    if cch_data == 0 {
        emu.reg_write(RegisterX86::RAX, required_size as u64)?;
        return Ok(());
    }

    // Validate buffer pointer
    if lp_lc_data == 0 {
        log::warn!("[GetLocaleInfoW] Invalid parameter - null buffer");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }

    // Check if buffer is too small
    if cch_data < required_size {
        log::warn!("[GetLocaleInfoW] Buffer too small: {} < {}", cch_data, required_size);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER)?;
        emu.reg_write(RegisterX86::RAX, 0)?;
        return Ok(());
    }

    // Write the wide string to memory
    memory::write_wide_string_to_memory(emu, lp_lc_data, result)?;
    
    // Return number of characters written (including null terminator)
    emu.reg_write(RegisterX86::RAX, required_size as u64)?;
    
    Ok(())
}
