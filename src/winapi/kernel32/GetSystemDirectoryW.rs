use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

/*
GetSystemDirectoryW function (sysinfoapi.h)
11/19/2024
Retrieves the path of the system directory. The system directory contains system files such as dynamic-link libraries and drivers.

This function is provided primarily for compatibility. Applications should store code in the Program Files folder and persistent data in the Application Data folder in the user's profile. For more information, see ShGetFolderPath.

Syntax
C++

Copy
UINT GetSystemDirectoryW(
  [out] LPWSTR lpBuffer,
  [in]  UINT   uSize
);
Parameters
[out] lpBuffer

A pointer to the buffer to receive the path. This path does not end with a backslash unless the system directory is the root directory. For example, if the system directory is named Windows\System32 on drive C, the path of the system directory retrieved by this function is C:\Windows\System32.

[in] uSize

The maximum size of the buffer, in TCHARs.

Return value
If the function succeeds, the return value is the length, in TCHARs, of the string copied to the buffer, not including the terminating null character. If the length is greater than the size of the buffer, the return value is the size of the buffer required to hold the path, including the terminating null character.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
Applications should not create files in the system directory. If the user is running a shared version of the operating system, the application does not have write access to the system directory.
*/

pub fn GetSystemDirectoryW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // UINT GetSystemDirectoryW(
    //   [out] LPWSTR lpBuffer,  // RCX
    //   [in]  UINT   uSize      // RDX
    // )
    
    let lp_buffer = emu.reg_read(X86Register::RCX)?;
    let u_size = emu.reg_read(X86Register::RDX)? as u32;
    
    log::info!("[GetSystemDirectoryW] lpBuffer: 0x{:x}", lp_buffer);
    log::info!("[GetSystemDirectoryW] uSize: {} wide characters", u_size);
    
    // Mock system directory path
    let system_directory = "C:\\Windows\\System32";
    let system_dir_wide_len = system_directory.encode_utf16().count() as u32;
    let required_buffer_size = system_dir_wide_len + 1; // Include null terminator
    
    // Check if buffer is large enough
    if u_size == 0 || lp_buffer == 0 {
        // Return required buffer size (including null terminator)
        log::info!("[GetSystemDirectoryW] Buffer is NULL or size is 0, returning required size: {}", required_buffer_size);
        emu.reg_write(X86Register::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    if u_size < required_buffer_size {
        // Buffer too small - return required size (including null terminator)
        log::warn!("[GetSystemDirectoryW] Buffer too small: need {} wide characters, got {}", 
                  required_buffer_size, u_size);
        emu.reg_write(X86Register::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    // Buffer is large enough - write the system directory path
    // Convert to UTF-16 and write wide string
    let wide_chars: Vec<u16> = system_directory.encode_utf16().collect();
    let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
    for &wchar in &wide_chars {
        buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    
    // Write the wide string
    emu.mem_write(lp_buffer, &buffer)?;
    
    // Write null terminator (2 bytes for wide char)
    emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
    
    log::info!("[GetSystemDirectoryW] Wrote system directory: '{}'", system_directory);
    log::warn!("[GetSystemDirectoryW] Mock implementation - returned system directory: '{}'", system_directory);
    
    // Return the length of the string copied (NOT including null terminator)
    emu.reg_write(X86Register::RAX, system_dir_wide_len as u64)?;
    
    Ok(())
}