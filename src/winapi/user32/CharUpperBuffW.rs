use unicorn_engine::{Unicorn, RegisterX86};

/*
CharUpperBuffW function (winuser.h)
02/22/2024
Converts lowercase characters in a buffer to uppercase characters. The function converts the characters in place.

Syntax
C++

Copy
DWORD CharUpperBuffW(
  [in, out] LPWSTR lpsz,
  [in]      DWORD  cchLength
);
Parameters
[in, out] lpsz

Type: LPTSTR

A buffer containing one or more characters to be processed.

[in] cchLength

Type: DWORD

The size, in characters, of the buffer pointed to by lpsz.

The function examines each character, and converts lowercase characters to uppercase characters. The function examines the number of characters indicated by cchLength, even if one or more characters are null characters.

Return value
Type: DWORD

The return value is the number of characters processed.

For example, if CharUpperBuff("Zenith of API Sets", 10) succeeds, the return value is 10.

Remarks
Note that CharUpperBuff always maps lowercase I ("i") to uppercase I, even when the current language is Turkish or Azerbaijani. If you need a function that is linguistically sensitive in this respect, call LCMapString.

Conversion to Unicode in the ANSI version of the function is done with the system default locale in all cases.
*/

pub fn CharUpperBuffW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD CharUpperBuffW(
    //   [in, out] LPWSTR lpsz,       // RCX
    //   [in]      DWORD  cchLength   // RDX
    // )
    
    let lpsz = emu.reg_read(RegisterX86::RCX)?;
    let cch_length = emu.reg_read(RegisterX86::RDX)? as u32;
    
    log::info!("[CharUpperBuffW] lpsz: 0x{:x}", lpsz);
    log::info!("[CharUpperBuffW] cchLength: {} characters", cch_length);
    
    // Check for NULL pointer
    if lpsz == 0 {
        log::error!("[CharUpperBuffW] NULL buffer pointer");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 characters processed
        return Ok(());
    }
    
    // Check for zero length
    if cch_length == 0 {
        log::info!("[CharUpperBuffW] Zero length - no characters to process");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 characters processed
        return Ok(());
    }
    
    // Read the wide character buffer
    let buffer_size = (cch_length as usize) * 2; // 2 bytes per wide character
    let mut buffer = vec![0u8; buffer_size];
    emu.mem_read(lpsz, &mut buffer)?;
    
    // Convert bytes to wide characters
    let mut wide_chars: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    
    // Convert to string for logging (before conversion)
    let original_string = String::from_utf16_lossy(&wide_chars);
    log::info!("[CharUpperBuffW] Original buffer: '{}'", original_string);
    
    // Process each wide character - convert lowercase to uppercase
    let mut processed_count = 0;
    for wchar in &mut wide_chars {
        if let Some(ch) = char::from_u32(*wchar as u32) {
            // Convert to uppercase (simple ASCII-based approach)
            let uppercase_ch = ch.to_uppercase().next().unwrap_or(ch);
            *wchar = uppercase_ch as u16;
            processed_count += 1;
        } else {
            // Invalid Unicode character - leave unchanged but still count as processed
            processed_count += 1;
        }
    }
    
    // Convert back to bytes and write to memory
    let mut new_buffer = Vec::with_capacity(buffer_size);
    for &wchar in &wide_chars {
        new_buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    
    emu.mem_write(lpsz, &new_buffer)?;
    
    // Convert to string for logging (after conversion)
    let converted_string = String::from_utf16_lossy(&wide_chars);
    log::info!("[CharUpperBuffW] Converted buffer: '{}'", converted_string);
    
    log::warn!("[CharUpperBuffW] Mock implementation - processed {} characters", processed_count);
    
    // Return the number of characters processed
    emu.reg_write(RegisterX86::RAX, processed_count as u64)?;
    
    Ok(())
}