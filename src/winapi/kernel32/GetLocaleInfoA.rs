use unicorn_engine::{Unicorn, RegisterX86};

use crate::{emulation::memory, winapi::locale};

pub fn GetLocaleInfoA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers (same as W version)
    let locale = emu.reg_read(RegisterX86::ECX)? as u32;
    let lctype = emu.reg_read(RegisterX86::EDX)? as u32;
    let lp_lc_data = emu.reg_read(RegisterX86::R8D)?;
    let cch_data = emu.reg_read(RegisterX86::R9D)? as u32;

    log::debug!("[GetLocaleInfoA] locale: 0x{:x} lctype: 0x{:x} buffer: 0x{:x} size: {}",
        locale, lctype, lp_lc_data, cch_data);

    // Get the locale string based on type (exact same strings as W version)
    let result = locale::get_locale_mock(lctype);

    // Calculate required size in BYTES (including null terminator)
    let required_size = (result.len() + 1) as u32;

    // If cch_data is 0, return required buffer size
    if cch_data == 0 {
        emu.reg_write(RegisterX86::EAX, required_size as u64)?;
        return Ok(());
    }

    // Validate buffer pointer
    if lp_lc_data == 0 {
        log::warn!("[GetLocaleInfoA] Invalid parameter - null buffer");
        emu.reg_write(RegisterX86::EAX, 0)?;
        return Ok(());
    }

    // Check if buffer is too small
    if cch_data < required_size {
        log::warn!("[GetLocaleInfoA] Buffer too small: {} < {}", cch_data, required_size);
        emu.reg_write(RegisterX86::EAX, 0)?;
        return Ok(());
    }

    // Write the ANSI string to memory (not wide string)
    memory::write_string_to_memory(emu, lp_lc_data, result)?;
    
    // Return number of bytes written (including null terminator)
    emu.reg_write(RegisterX86::EAX, required_size as u64)?;
    
    Ok(())
}
