use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::winapi;

/*
GetComputerNameW function (winbase.h)
11/19/2024
Retrieves the NetBIOS name of the local computer. This name is established at system startup, when the system reads it from the registry.

GetComputerName retrieves only the NetBIOS name of the local computer. To retrieve the DNS host name, DNS domain name, or the fully qualified DNS name, call the GetComputerNameEx function. Additional information is provided by the IADsADSystemInfo interface.

The behavior of this function can be affected if the local computer is a node in a cluster. For more information, see ResUtilGetEnvironmentWithNetName and UseNetworkName.

Syntax
C++

Copy
BOOL GetComputerNameW(
  [out]     LPWSTR  lpBuffer,
  [in, out] LPDWORD nSize
);
Parameters
[out] lpBuffer

A pointer to a buffer that receives the computer name or the cluster virtual server name. The buffer size should be large enough to contain MAX_COMPUTERNAME_LENGTH + 1 characters.

[in, out] nSize

On input, specifies the size of the buffer, in TCHARs. On output, the number of TCHARs copied to the destination buffer, not including the terminating null character.

If the buffer is too small, the function fails and GetLastError returns ERROR_BUFFER_OVERFLOW. The lpnSize parameter specifies the size of the buffer required, including the terminating null character.

Return value
If the function succeeds, the return value is a nonzero value.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
The GetComputerName function retrieves the NetBIOS name established at system startup. Name changes made by the SetComputerName or SetComputerNameEx functions do not take effect until the user restarts the computer.

If the caller is running under a client session, this function returns the server name. To retrieve the client name, use the WTSQuerySessionInformation function.
*/

pub fn GetComputerNameW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL GetComputerNameW(
    //   [out]     LPWSTR  lpBuffer,  // RCX
    //   [in, out] LPDWORD nSize      // RDX
    // )
    
    let lp_buffer = emu.reg_read(X86Register::RCX)?;
    let n_size = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[GetComputerNameW] lpBuffer: 0x{:x}", lp_buffer);
    log::info!("[GetComputerNameW] nSize: 0x{:x}", n_size);
    
    // Check for NULL nSize pointer
    if n_size == 0 {
        log::error!("[GetComputerNameW] NULL nSize pointer");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Read the buffer size (in wide characters)
    let mut buffer_size_bytes = [0u8; 4];
    emu.mem_read(n_size, &mut buffer_size_bytes)?;
    let buffer_size = u32::from_le_bytes(buffer_size_bytes);
    
    log::info!("[GetComputerNameW] Buffer size: {} wide characters", buffer_size);
    
    // Mock computer name (NetBIOS name - typically uppercase and limited to 15 chars)
    let computer_name = "TESTCOMPUTER";
    let computer_name_wide_len = computer_name.encode_utf16().count() as u32;
    let required_buffer_size = computer_name_wide_len + 1; // Include null terminator
    
    // Check if buffer is large enough (in wide characters)
    if buffer_size < required_buffer_size {
        log::warn!("[GetComputerNameW] Buffer too small: need {} wide characters, got {}", 
                  required_buffer_size, buffer_size);
        
        // Write required size back to nSize (including null terminator)
        let required_size_bytes = required_buffer_size.to_le_bytes();
        emu.mem_write(n_size, &required_size_bytes)?;
        
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Write computer name to buffer if lpBuffer is provided
    if lp_buffer != 0 {
        // Convert to UTF-16 and write wide string
        let wide_chars: Vec<u16> = computer_name.encode_utf16().collect();
        let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
        for &wchar in &wide_chars {
            buffer.extend_from_slice(&wchar.to_le_bytes());
        }
        
        // Write the wide string
        emu.mem_write(lp_buffer, &buffer)?;
        
        // Write null terminator (2 bytes for wide char)
        emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
        
        log::info!("[GetComputerNameW] Wrote computer name: '{}'", computer_name);
    }
    
    // Write actual length to nSize (NOT including null terminator, per API spec, in wide characters)
    let actual_size_bytes = computer_name_wide_len.to_le_bytes();
    emu.mem_write(n_size, &actual_size_bytes)?;
    
    log::warn!("[GetComputerNameW] Mock implementation - returned computer name: '{}'", computer_name);
    
    // Return TRUE (success)
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}