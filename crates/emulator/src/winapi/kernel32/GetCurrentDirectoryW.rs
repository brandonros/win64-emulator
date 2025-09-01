use unicorn_engine::{Unicorn, RegisterX86};

/*
pub unsafe extern "system" fn GetCurrentDirectoryW(
    nbufferlength: u32,
    lpbuffer: PWSTR,
) -> u32
*/

/*
GetCurrentDirectory function (winbase.h)
10/12/2021
Retrieves the current directory for the current process.

Syntax
C++

Copy
DWORD GetCurrentDirectory(
  [in]  DWORD  nBufferLength,
  [out] LPTSTR lpBuffer
);
Parameters
[in] nBufferLength

The length of the buffer for the current directory string, in TCHARs. The buffer length must include room for a terminating null character.

[out] lpBuffer

A pointer to the buffer that receives the current directory string. This null-terminated string specifies the absolute path to the current directory.

To determine the required buffer size, set this parameter to NULL and the nBufferLength parameter to 0.

Return value
If the function succeeds, the return value specifies the number of characters that are written to the buffer, not including the terminating null character.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

If the buffer that is pointed to by lpBuffer is not large enough, the return value specifies the required size of the buffer, in characters, including the null-terminating character.

Remarks
Each process has a single current directory that consists of two parts:

A disk designator that is either a drive letter followed by a colon, or a server name followed by a share name (\\servername\sharename)
A directory on the disk designator
To set the current directory, use the SetCurrentDirectory function.
Multithreaded applications and shared library code should not use the
GetCurrentDirectory function and should avoid using relative path names. The current directory state written by the SetCurrentDirectory function is stored as a global variable in each process, therefore multithreaded applications cannot reliably use this value without possible data corruption from other threads that may also be reading or setting this value. This limitation also applies to the SetCurrentDirectory and GetFullPathName functions. The exception being when the application is guaranteed to be running in a single thread, for example parsing file names from the command line argument string in the main thread prior to creating any additional threads. Using relative path names in multithreaded applications or shared library code can yield unpredictable results and is not supported.

In Windows 8 and Windows Server 2012, this function is supported by the following technologies.
*/

pub fn GetCurrentDirectoryW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetCurrentDirectoryW(
    //   [in]  DWORD  nBufferLength,  // RCX
    //   [out] LPWSTR lpBuffer        // RDX
    // )
    
    let n_buffer_length = emu.reg_read(RegisterX86::RCX)? as u32;
    let lp_buffer = emu.reg_read(RegisterX86::RDX)?;
    
    log::info!("[GetCurrentDirectoryW] nBufferLength: {} wide characters", n_buffer_length);
    log::info!("[GetCurrentDirectoryW] lpBuffer: 0x{:x}", lp_buffer);
    
    // Mock current directory
    let current_dir = "C:\\Program Files\\Application";
    let current_dir_wide_len = current_dir.encode_utf16().count() as u32;
    let required_buffer_size = current_dir_wide_len + 1; // Include null terminator
    
    // If buffer is NULL or size is 0, return required buffer size
    if lp_buffer == 0 || n_buffer_length == 0 {
        log::info!("[GetCurrentDirectoryW] Buffer is NULL or size is 0, returning required size: {}", required_buffer_size);
        emu.reg_write(RegisterX86::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    // Check if buffer is large enough
    if n_buffer_length < required_buffer_size {
        // Buffer too small - return required size (including null terminator)
        log::warn!("[GetCurrentDirectoryW] Buffer too small: need {} wide characters, got {}", 
                  required_buffer_size, n_buffer_length);
        emu.reg_write(RegisterX86::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    // Write the current directory path to buffer
    let wide_chars: Vec<u16> = current_dir.encode_utf16().collect();
    let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
    for &wchar in &wide_chars {
        buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    
    // Write the wide string
    emu.mem_write(lp_buffer, &buffer)?;
    
    // Write null terminator (2 bytes for wide char)
    emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
    
    log::info!("[GetCurrentDirectoryW] Wrote current directory: '{}'", current_dir);
    log::warn!("[GetCurrentDirectoryW] Mock implementation - returned current directory: '{}'", current_dir);
    
    // Return the length of the string copied (NOT including null terminator)
    emu.reg_write(RegisterX86::RAX, current_dir_wide_len as u64)?;
    
    Ok(())
}