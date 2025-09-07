/*use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use windows_sys::Win32::Globalization::{CP_ACP, CP_UTF7, CP_UTF8};
use crate::emulation::memory;
use crate::winapi;

pub fn WideCharToMultiByte(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let code_page = emu.reg_read(X86Register::RCX)? as u32;
    let dw_flags = emu.reg_read(X86Register::RDX)? as u32;
    let lp_wide_char_str = emu.reg_read(X86Register::R8)?;
    let cch_wide_char = emu.reg_read(X86Register::R9)? as i32;
    
    // Get stack parameters (5th-8th parameters)
    // Shadow space (0x20) + actual parameters
    let rsp = emu.reg_read(X86Register::RSP)?;
    let lp_multi_byte_str = {
        let bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
        u64::from_le_bytes(bytes.try_into().unwrap())
    };
    let cb_multi_byte = {
        let bytes = emu.mem_read_as_vec(rsp + 0x30, 8)?;
        u64::from_le_bytes(bytes.try_into().unwrap()) as i32
    };
    let lp_default_char = {
        let bytes = emu.mem_read_as_vec(rsp + 0x38, 8)?;
        u64::from_le_bytes(bytes.try_into().unwrap())
    };
    let lp_used_default_char = {
        let bytes = emu.mem_read_as_vec(rsp + 0x40, 8)?;
        u64::from_le_bytes(bytes.try_into().unwrap())
    };

    log::info!("[WideCharToMultiByte] CodePage: {}, dwFlags: {}, lpWideCharStr: 0x{:x}, cchWideChar: {}, lpMultiByteStr: 0x{:x}, cbMultiByte: {}, lpDefaultChar: 0x{:x}, lpUsedDefaultChar: 0x{:x}",
        code_page, dw_flags, lp_wide_char_str, cch_wide_char, 
        lp_multi_byte_str, cb_multi_byte, lp_default_char, lp_used_default_char
    );

    // 1. Input validation
    if lp_wide_char_str == 0 {
        log::warn!("[WideCharToMultiByte] Invalid parameter: lpWideCharStr is NULL");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }

    // 2. Handle special code pages (UTF-7 and UTF-8)
    if code_page == windows_sys::Win32::Globalization::CP_UTF7 || code_page == windows_sys::Win32::Globalization::CP_UTF8 {
        if lp_default_char != 0 || lp_used_default_char != 0 {
            log::warn!("[WideCharToMultiByte] Invalid parameter: UTF-7/UTF-8 cannot use default char");
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
    }

    // 3. Read input string and get its length
    let wide_string = if cch_wide_char == -1 {
        // Read null-terminated wide string
        memory::read_wide_string_from_memory(emu, lp_wide_char_str)?
    } else {
        // Read specific number of wide chars
        let mut wide_data = Vec::new();
        for i in 0..cch_wide_char {
            let addr = lp_wide_char_str + (i * 2) as u64;
            let word = emu.mem_read_as_vec(addr, 2)?;
            let wide_char = u16::from_le_bytes([word[0], word[1]]);
            wide_data.push(wide_char);
        }
        String::from_utf16_lossy(&wide_data)
    };

    let input_len = wide_string.len();

    // 4. If this is just a size query (cbMultiByte == 0)
    if cb_multi_byte == 0 {
        let required_size = if cch_wide_char == -1 {
            input_len + 1  // Include null terminator
        } else {
            input_len
        };
        emu.reg_write(X86Register::RAX, required_size as u64)?;
        winapi::set_last_error(emu, 0)?;
        log::info!("[WideCharToMultiByte] Size query: returning {}", required_size);
        return Ok(());
    }

    // 5. Convert string based on code page
    let (multi_byte_data, used_default) = convert_wide_to_multibyte(
        &wide_string, 
        code_page, 
        lp_default_char
    )?;

    let bytes_needed = if cch_wide_char == -1 {
        multi_byte_data.len() + 1  // Include null terminator
    } else {
        multi_byte_data.len()
    };

    // 6. Check output buffer size
    if cb_multi_byte < bytes_needed as i32 {
        log::warn!("[WideCharToMultiByte] Buffer too small: need {} bytes, have {}", 
                  bytes_needed, cb_multi_byte);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER)?;
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }

    // 7. Perform the actual conversion
    if lp_multi_byte_str != 0 && !multi_byte_data.is_empty() {
        // Write the converted string
        emu.mem_write(lp_multi_byte_str, &multi_byte_data)?;
        
        // Write null terminator if needed
        if cch_wide_char == -1 {
            emu.mem_write(lp_multi_byte_str + multi_byte_data.len() as u64, &[0u8])?;
        }

        // Set used default char flag if requested
        if lp_used_default_char != 0 {
            let used_flag: u32 = if used_default { 1 } else { 0 };
            emu.mem_write(lp_used_default_char, &used_flag.to_le_bytes())?;
        }
    }

    // 8. Return number of bytes written
    emu.reg_write(X86Register::RAX, bytes_needed as u64)?;
    winapi::set_last_error(emu, 0)?;

    // Log the conversion
    log::info!("[WideCharToMultiByte] Converted \"{}\" ({} chars) to {} bytes",
              wide_string.escape_debug(), input_len, bytes_needed);

    Ok(())
}

// Helper function to convert wide string to multibyte based on code page
fn convert_wide_to_multibyte(
    wide_string: &str, 
    code_page: u32,
    lp_default_char: u64
) -> Result<(Vec<u8>, bool), EmulatorError> {
    let mut used_default = false;
    
    let multi_byte_data = match code_page {
        CP_UTF8 => {
            // UTF-8 conversion
            wide_string.as_bytes().to_vec()
        },
        CP_UTF7 => {
            // UTF-7 conversion (simplified - real UTF-7 is more complex)
            // For now, just use ASCII-safe encoding
            wide_string.chars().map(|c| {
                if c as u32 <= 127 {
                    c as u8
                } else {
                    used_default = true;
                    b'?'
                }
            }).collect()
        },
        CP_ACP | 1252 => {
            // ANSI/Windows-1252 codepage
            wide_string.chars().map(|c| {
                if c as u32 <= 255 {
                    c as u8
                } else {
                    used_default = true;
                    // Use provided default char or '?'
                    if lp_default_char != 0 {
                        // Would need to read the default char from memory
                        // For simplicity, using '?'
                        b'?'
                    } else {
                        b'?'
                    }
                }
            }).collect()
        },
        _ => {
            // Other code pages - simplified handling
            wide_string.chars().map(|c| {
                if c as u32 <= 255 {
                    c as u8
                } else {
                    used_default = true;
                    b'?'
                }
            }).collect()
        }
    };
    
    Ok((multi_byte_data, used_default))
}*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;

pub fn WideCharToMultiByte(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let code_page = emu.reg_read(X86Register::RCX)? as u32;
    let _dw_flags = emu.reg_read(X86Register::RDX)? as u32;
    let lp_wide_char_str = emu.reg_read(X86Register::R8)?;
    let cch_wide_char = emu.reg_read(X86Register::R9)? as i32;
    
    // Get stack parameters (5th and 6th parameters)
    let rsp = emu.reg_read(X86Register::RSP)?;
    let lp_multi_byte_str = emu.mem_read_as_vec(rsp + 0x28, 8)?; // TODO: 0x20 or 0x28
    let lp_multi_byte_str = u64::from_le_bytes(lp_multi_byte_str.try_into().unwrap());
    let cb_multi_byte = emu.mem_read_as_vec(rsp + 0x30, 4)?; // TODO: 0x28 or 0x30
    let cb_multi_byte = i32::from_le_bytes(cb_multi_byte.try_into().unwrap());
    
    log::info!("[WideCharToMultiByte] CodePage: {}, lpWideCharStr: 0x{:x}, cchWideChar: {}, lpMultiByteStr: 0x{:x}, cbMultiByte: {}", 
              code_page, lp_wide_char_str, cch_wide_char, lp_multi_byte_str, cb_multi_byte);
    
    // Validate input parameters
    if lp_wide_char_str == 0 && cch_wide_char != 0 {
        log::warn!("[WideCharToMultiByte] Invalid parameter: lpWideCharStr is NULL with non-zero cchWideChar");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // Handle NULL input (return 0)
    if lp_wide_char_str == 0 {
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
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
        emu.reg_write(X86Register::RAX, required_size as u64)?;
        log::info!("[WideCharToMultiByte] Returning required size: {}", required_size);
        return Ok(());
    }
    
    // Check if buffer is large enough
    if cb_multi_byte < required_size as i32 {
        // ERROR_INSUFFICIENT_BUFFER
        emu.reg_write(X86Register::RAX, 0)?;
        log::warn!("[WideCharToMultiByte] Buffer too small");
        return Ok(());
    }
    
    // Write the converted string
    if lp_multi_byte_str != 0 {
        emu.mem_write(lp_multi_byte_str, &multi_byte_data)?;
    }
    
    // Return number of bytes written
    emu.reg_write(X86Register::RAX, required_size as u64)?;
    
    log::info!("[WideCharToMultiByte] Converted '{}' to {} bytes", 
              wide_string, required_size);
    
    Ok(())
}