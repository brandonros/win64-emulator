use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

/*
CharLowerBuffW function (winuser.h)
11/19/2024
Converts uppercase characters in a buffer to lowercase characters. The function converts the characters in place.

Syntax
C++

Copy
DWORD CharLowerBuffW(
  [in, out] LPWSTR lpsz,
  [in]      DWORD  cchLength
);
Parameters
[in, out] lpsz

Type: LPTSTR

A buffer containing one or more characters to be processed.

[in] cchLength

Type: DWORD

The size, in characters, of the buffer pointed to by lpsz. The function examines each character, and converts uppercase characters to lowercase characters. The function examines the number of characters indicated by cchLength, even if one or more characters are null characters.

Return value
Type: DWORD

The return value is the number of characters processed. For example, if CharLowerBuff("Acme of Operating Systems", 10) succeeds, the return value is 10.

Remarks
Note that CharLowerBuff always maps uppercase I to lowercase I ("i"), even when the current language is Turkish or Azerbaijani. If you need a function that is linguistically sensitive in this respect, call LCMapSting.

Conversion to Unicode in the ANSI version of the function is done with the system default locale in all cases.
*/

pub fn CharLowerBuffW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // DWORD CharLowerBuffW(
    //   [in, out] LPWSTR lpsz,       // RCX
    //   [in]      DWORD  cchLength   // RDX
    // )
    
    let lpsz = emu.reg_read(X86Register::RCX)?;
    let cch_length = emu.reg_read(X86Register::RDX)? as u32;
    
    log::info!("[CharLowerBuffW] lpsz: 0x{:x}", lpsz);
    log::info!("[CharLowerBuffW] cchLength: {} characters", cch_length);
    
    // Check for NULL pointer
    if lpsz == 0 {
        log::error!("[CharLowerBuffW] NULL buffer pointer");
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 characters processed
        return Ok(());
    }
    
    // Check for zero length
    if cch_length == 0 {
        log::info!("[CharLowerBuffW] Zero length - no characters to process");
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 characters processed
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
    log::info!("[CharLowerBuffW] Original buffer: '{}'", original_string);
    
    // Process each wide character - convert uppercase to lowercase
    let mut processed_count = 0;
    for wchar in &mut wide_chars {
        if let Some(ch) = char::from_u32(*wchar as u32) {
            // Convert to lowercase (simple ASCII-based approach)
            let lowercase_ch = ch.to_lowercase().next().unwrap_or(ch);
            *wchar = lowercase_ch as u16;
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
    log::info!("[CharLowerBuffW] Converted buffer: '{}'", converted_string);
    
    log::warn!("[CharLowerBuffW] Mock implementation - processed {} characters", processed_count);
    
    // Return the number of characters processed
    emu.reg_write(X86Register::RAX, processed_count as u64)?;
    
    Ok(())
}