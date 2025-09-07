use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn MultiByteToWideChar(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // int MultiByteToWideChar(
    //   UINT   CodePage,       // RCX
    //   DWORD  dwFlags,        // RDX
    //   LPCSTR lpMultiByteStr, // R8
    //   int    cbMultiByte,    // R9 (EDX for 32-bit int)
    //   LPWSTR lpWideCharStr,  // [RSP+0x20] (not 0x40!)
    //   int    cchWideChar     // [RSP+0x28] (not 0x48!)
    // )
    
    let code_page = emu.reg_read(X86Register::RCX)? as u32;
    let flags = emu.reg_read(X86Register::RDX)? as u32;
    let multi_byte_str = emu.reg_read(X86Register::R8)?;
    let cb_multi_byte = emu.reg_read(X86Register::R9)? as i32;
    
    // Read stack parameters - CORRECTED OFFSETS
    let rsp = emu.reg_read(X86Register::RSP)?;
    let mut wide_char_str_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x20, &mut wide_char_str_bytes)?;  // Fixed: was 0x40
    let wide_char_str = u64::from_le_bytes(wide_char_str_bytes);
    
    let mut cch_wide_char_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x28, &mut cch_wide_char_bytes)?;  // Fixed: was 0x48
    let cch_wide_char = i32::from_le_bytes(cch_wide_char_bytes);
    
    // ENHANCED VALIDATION
    if wide_char_str == 0 && cch_wide_char > 0 {
        log::warn!("[MultiByteToWideChar] Output buffer is NULL but cch_wide_char = {}", cch_wide_char);
        // This is actually invalid - should return 0 and set error
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    if wide_char_str != 0 && cch_wide_char == 0 {
        log::warn!("[MultiByteToWideChar] Output buffer is non-NULL but cch_wide_char = 0");
    }
    
    if cch_wide_char < 0 || cch_wide_char > 1_000_000 {
        log::warn!("[MultiByteToWideChar] Suspicious cch_wide_char = {}", cch_wide_char);
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    if cb_multi_byte < -1 || cb_multi_byte > 10_000_000 {
        log::warn!("[MultiByteToWideChar] Suspicious cb_multi_byte = {}", cb_multi_byte);
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // Check for NULL source string
    if multi_byte_str == 0 {
        log::warn!("[MultiByteToWideChar] NULL source string");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // IMPROVED STRING READING
    let source_string = if cb_multi_byte == -1 {
        // Read null-terminated string
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        loop {
            let mut byte = [0u8; 1];
            emu.mem_read(multi_byte_str + offset, &mut byte)?;
            if byte[0] == 0 {
                break;
            }
            bytes.push(byte[0]);
            offset += 1;
            if offset > 4096 {  // Sanity check
                log::warn!("[MultiByteToWideChar] String too long, truncating");
                break;
            }
        }
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        // Read exact number of bytes
        let mut source_bytes = vec![0u8; cb_multi_byte as usize];
        emu.mem_read(multi_byte_str, &mut source_bytes)?;
        String::from_utf8_lossy(&source_bytes).to_string()
    };
    
    // PROPER UTF-8 TO UTF-16 CONVERSION
    let wide_chars: Vec<u16> = source_string.encode_utf16().collect();
    
    log::info!("[MultiByteToWideChar] CodePage: {}, dwFlags: 0x{:x}", code_page, flags);
    log::info!("[MultiByteToWideChar] Input: \"{}\" ({} bytes -> {} wide chars)", 
              source_string.escape_debug(), source_string.len(), wide_chars.len());
    
    // If cchWideChar is 0, return the required buffer size (in wide characters, not bytes!)
    if cch_wide_char == 0 {
        log::info!("[MultiByteToWideChar] Query mode - returning required size: {} wide chars", wide_chars.len());
        emu.reg_write(X86Register::RAX, wide_chars.len() as u64)?;
        return Ok(());
    }
    
    // Check buffer size and write if sufficient
    if wide_char_str != 0 {
        if cch_wide_char >= wide_chars.len() as i32 {
            // Write the wide characters
            for (i, &wchar) in wide_chars.iter().enumerate() {
                emu.mem_write(wide_char_str + (i * 2) as u64, &wchar.to_le_bytes())?;
            }
            
            log::info!("[MultiByteToWideChar] Successfully converted {} wide characters", wide_chars.len());
            emu.reg_write(X86Register::RAX, wide_chars.len() as u64)?;
        } else {
            log::warn!("[MultiByteToWideChar] Buffer too small: need {} but got {}", wide_chars.len(), cch_wide_char);
            // Should set ERROR_INSUFFICIENT_BUFFER here
            emu.reg_write(X86Register::RAX, 0)?;
        }
    } else {
        // Invalid parameter - non-zero cch but null buffer
        log::warn!("[MultiByteToWideChar] Invalid parameter: null buffer with non-zero size");
        emu.reg_write(X86Register::RAX, 0)?;
    }
    
    Ok(())
}