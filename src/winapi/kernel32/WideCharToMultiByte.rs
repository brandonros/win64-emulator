use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

use crate::emulation::memory;

pub fn WideCharToMultiByte(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers (x64 calling convention)
    let code_page = emu.reg_read(RegisterX86::RCX)? as u32;
    let _dw_flags = emu.reg_read(RegisterX86::RDX)? as u32;
    let lp_wide_char_str = emu.reg_read(RegisterX86::R8)?;
    let cch_wide_char = emu.reg_read(RegisterX86::R9)? as i32;
    
    // Get stack parameters (5th and 6th parameters)
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let lp_multi_byte_str = emu.mem_read_as_vec(rsp + 0x28, 8)?; // TODO: 0x20 or 0x28
    let lp_multi_byte_str = u64::from_le_bytes(lp_multi_byte_str.try_into().unwrap());
    let cb_multi_byte = emu.mem_read_as_vec(rsp + 0x30, 4)?; // TODO: 0x28 or 0x30
    let cb_multi_byte = i32::from_le_bytes(cb_multi_byte.try_into().unwrap());
    
    log::info!("[WideCharToMultiByte] CodePage: {}, lpWideCharStr: 0x{:x}, cchWideChar: {}, lpMultiByteStr: 0x{:x}, cbMultiByte: {}", 
              code_page, lp_wide_char_str, cch_wide_char, lp_multi_byte_str, cb_multi_byte);
    
    // Read the wide string
    let wide_string = if cch_wide_char == -1 {
        // Use the helper function for null-terminated strings
        memory::read_wide_string_from_memory(emu, lp_wide_char_str)?
    } else {
        // Read specific number of wide chars
        let mut wide_data = Vec::new();
        for i in 0..cch_wide_char {
            let word = emu.mem_read_as_vec(lp_wide_char_str + (i * 2) as u64, 2)?;
            wide_data.push(u16::from_le_bytes([word[0], word[1]]));
        }
        String::from_utf16_lossy(&wide_data)
    };
    
    // Convert to bytes (simplified - proper codepage conversion would be more complex)
    let multi_byte_data = if code_page == 65001 {
        // UTF-8
        wide_string.as_bytes().to_vec()
    } else {
        // Simple ANSI/ASCII - just take chars < 256
        wide_string.chars()
            .map(|c| if c as u32 <= 255 { c as u8 } else { b'?' })
            .collect()
    };
    
    let required_size = multi_byte_data.len();
    
    // If cbMultiByte is 0, just return required size
    if cb_multi_byte == 0 {
        emu.reg_write(RegisterX86::RAX, required_size as u64)?;
        log::info!("[WideCharToMultiByte] Returning required size: {}", required_size);
        return Ok(());
    }
    
    // Check if buffer is large enough
    if cb_multi_byte < required_size as i32 {
        // ERROR_INSUFFICIENT_BUFFER
        emu.reg_write(RegisterX86::RAX, 0)?;
        log::warn!("[WideCharToMultiByte] Buffer too small");
        return Ok(());
    }
    
    // Write the converted string
    if lp_multi_byte_str != 0 {
        emu.mem_write(lp_multi_byte_str, &multi_byte_data)?;
    }
    
    // Return number of bytes written
    emu.reg_write(RegisterX86::RAX, required_size as u64)?;
    
    log::info!("[WideCharToMultiByte] Converted '{}' to {} bytes", 
              wide_string, required_size);
    
    Ok(())
}