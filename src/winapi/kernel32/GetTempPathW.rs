use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

/*
GetTempPathW function (fileapi.h)
11/19/2024
Retrieves the path of the directory designated for temporary files.

Syntax
C++

Copy
DWORD GetTempPathW(
  [in]  DWORD  nBufferLength,
  [out] LPWSTR lpBuffer
);
Parameters
[in] nBufferLength

The size of the string buffer identified by lpBuffer, in TCHARs.

[out] lpBuffer

A pointer to a string buffer that receives the null-terminated string specifying the temporary file path. The returned string ends with a backslash, for example, "C:\TEMP\".

Return value
If the function succeeds, the return value is the length, in TCHARs, of the string copied to lpBuffer, not including the terminating null character. If the return value is greater than nBufferLength, the return value is the length, in TCHARs, of the buffer required to hold the path.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

The maximum possible return value is MAX_PATH+1 (261).
*/

pub fn GetTempPathW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // DWORD GetTempPathW(
    //   [in]  DWORD  nBufferLength,  // RCX
    //   [out] LPWSTR lpBuffer        // RDX
    // )
    
    let n_buffer_length = emu.reg_read(X86Register::RCX)? as u32;
    let lp_buffer = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[GetTempPathW] nBufferLength: {} wide characters", n_buffer_length);
    log::info!("[GetTempPathW] lpBuffer: 0x{:x}", lp_buffer);
    
    // Mock temp path with trailing backslash (as specified by API)
    let temp_path = "C:\\Temp\\";
    let temp_path_wide_len = temp_path.encode_utf16().count() as u32;
    let required_buffer_size = temp_path_wide_len + 1; // Include null terminator
    
    // Check if buffer is large enough
    if lp_buffer == 0 || n_buffer_length < required_buffer_size {
        // Return required buffer size (including null terminator) when buffer too small
        log::warn!("[GetTempPathW] Buffer too small or NULL: need {} wide characters, got {}", 
                  required_buffer_size, n_buffer_length);
        emu.reg_write(X86Register::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    // Write the temp path to buffer
    let wide_chars: Vec<u16> = temp_path.encode_utf16().collect();
    let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
    for &wchar in &wide_chars {
        buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    
    // Write the wide string
    emu.mem_write(lp_buffer, &buffer)?;
    
    // Write null terminator (2 bytes for wide char)
    emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
    
    log::info!("[GetTempPathW] Wrote temp path: '{}'", temp_path);
    log::warn!("[GetTempPathW] Mock implementation - returned temp path: '{}'", temp_path);
    
    // Return the length of the string copied (NOT including null terminator)
    emu.reg_write(X86Register::RAX, temp_path_wide_len as u64)?;
    
    Ok(())
}