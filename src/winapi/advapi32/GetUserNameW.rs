use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::winapi;

/*
GetUserNameW function (winbase.h)
02/08/2023
Retrieves the name of the user associated with the current thread.

Use the GetUserNameEx function to retrieve the user name in a specified format. Additional information is provided by the IADsADSystemInfo interface.

Syntax
C++

Copy
BOOL GetUserNameW(
  [out]     LPWSTR  lpBuffer,
  [in, out] LPDWORD pcbBuffer
);
Parameters
[out] lpBuffer

A pointer to the buffer to receive the user's logon name. If this buffer is not large enough to contain the entire user name, the function fails. A buffer size of (UNLEN + 1) characters will hold the maximum length user name including the terminating null character. UNLEN is defined in Lmcons.h.

[in, out] pcbBuffer

On input, this variable specifies the size of the lpBuffer buffer, in TCHARs. On output, the variable receives the number of TCHARs copied to the buffer, including the terminating null character.

If lpBuffer is too small, the function fails and GetLastError returns ERROR_INSUFFICIENT_BUFFER. This parameter receives the required buffer size, including the terminating null character.

Return value
If the function succeeds, the return value is a nonzero value, and the variable pointed to by lpnSize contains the number of TCHARs copied to the buffer specified by lpBuffer, including the terminating null character.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
If the current thread is impersonating another client, the GetUserName function returns the user name of the client that the thread is impersonating.

If GetUserName is called from a process that is running under the "NETWORK SERVICE" account, the string returned in lpBuffer may be different depending on the version of Windows. On Windows XP, the "NETWORK SERVICE" string is returned. On Windows Vista, the "<HOSTNAME>$" string is returned.


*/

pub fn GetUserNameW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL GetUserNameW(
    //   [out]     LPWSTR  lpBuffer,    // RCX
    //   [in, out] LPDWORD pcbBuffer    // RDX
    // )
    
    let lp_buffer = emu.reg_read(X86Register::RCX)?;
    let pcb_buffer = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[GetUserNameW] lpBuffer: 0x{:x}", lp_buffer);
    log::info!("[GetUserNameW] pcbBuffer: 0x{:x}", pcb_buffer);
    
    // Check for NULL pointers
    if pcb_buffer == 0 {
        log::error!("[GetUserNameW] NULL pcbBuffer pointer");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Read the buffer size (in wide characters)
    let mut buffer_size_bytes = [0u8; 4];
    emu.mem_read(pcb_buffer, &mut buffer_size_bytes)?;
    let buffer_size = u32::from_le_bytes(buffer_size_bytes);
    
    log::info!("[GetUserNameW] Buffer size: {} wide characters", buffer_size);
    
    // Mock username
    let username = "TestUser";
    let username_wide_len = username.encode_utf16().count() as u32 + 1; // Include null terminator
    
    // Check if buffer is large enough (in wide characters)
    if buffer_size < username_wide_len {
        log::warn!("[GetUserNameW] Buffer too small: need {} wide characters, got {}", username_wide_len, buffer_size);
        
        // Write required size back to pcbBuffer
        let required_size_bytes = username_wide_len.to_le_bytes();
        emu.mem_write(pcb_buffer, &required_size_bytes)?;
        
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Write username to buffer if lpBuffer is provided
    if lp_buffer != 0 {
        // Convert to UTF-16 and write wide string
        let wide_chars: Vec<u16> = username.encode_utf16().collect();
        let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
        for &wchar in &wide_chars {
            buffer.extend_from_slice(&wchar.to_le_bytes());
        }
        
        // Write the wide string
        emu.mem_write(lp_buffer, &buffer)?;
        
        // Write null terminator (2 bytes for wide char)
        emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
        
        log::info!("[GetUserNameW] Wrote username: '{}'", username);
    }
    
    // Write actual length to pcbBuffer (including null terminator, in wide characters)
    let actual_size_bytes = username_wide_len.to_le_bytes();
    emu.mem_write(pcb_buffer, &actual_size_bytes)?;
    
    log::warn!("[GetUserNameW] Mock implementation - returned username: '{}'", username);
    
    // Return TRUE (success)
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}