use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;

/*
etFullPathNameW function (fileapi.h)
06/01/2023
Retrieves the full path and file name of the specified file.

To perform this operation as a transacted operation, use the GetFullPathNameTransacted function.

For more information about file and path names, see File Names, Paths, and Namespaces.

Note See the Remarks section for discussion of the use of relative paths with the GetFullPathName function in multithreaded applications or shared library code.
Syntax
C++

Copy
DWORD GetFullPathNameW(
  [in]  LPCWSTR lpFileName,
  [in]  DWORD   nBufferLength,
  [out] LPWSTR  lpBuffer,
  [out] LPWSTR  *lpFilePart
);
Parameters
[in] lpFileName

The name of the file.

This parameter can be a short (the 8.3 form) or long file name. This string can also be a share or volume name.

By default, the name is limited to MAX_PATH characters. To extend this limit to 32,767 wide characters, prepend "\\?\" to the path. For more information, see Naming Files, Paths, and Namespaces.

 Tip

Starting with Windows 10, Version 1607, you can opt-in to remove the MAX_PATH limitation without prepending "\\?\". See the "Maximum Path Length Limitation" section of Naming Files, Paths, and Namespaces for details.

[in] nBufferLength

The size of the buffer to receive the null-terminated string for the drive and path, in TCHARs.

[out] lpBuffer

A pointer to a buffer that receives the null-terminated string for the drive and path.

[out] lpFilePart

A pointer to a buffer that receives the address (within lpBuffer) of the final file name component in the path.

This parameter can be NULL.

If lpBuffer refers to a directory and not a file, lpFilePart receives zero.

Return value
If the function succeeds, the return value is the length, in TCHARs, of the string copied to lpBuffer, not including the terminating null character.

If the lpBuffer buffer is too small to contain the path, the return value is the size, in TCHARs, of the buffer that is required to hold the path and the terminating null character.

If the function fails for any other reason, the return value is zero. To get extended error information, call GetLastError.

Remarks
GetFullPathName merges the name of the current drive and directory with a specified file name to determine the full path and file name of a specified file. It also calculates the address of the file name portion of the full path and file name.

This function does not verify that the resulting path and file name are valid, or that they see an existing file on the associated volume.

Note that the lpFilePart parameter does not require string buffer space, but only enough for a single address. This is because it simply returns an address within the buffer that already exists for lpBuffer.

Share and volume names are valid input for lpFileName. For example, the following list identities the returned path and file names if test-2 is a remote computer and U: is a network mapped drive whose current directory is the root of the volume:

If you specify "\\test-2\q$\lh" the path returned is "\\test-2\q$\lh"
If you specify "\\?\UNC\test-2\q$\lh" the path returned is "\\?\UNC\test-2\q$\lh"
If you specify "U:" the path returned is the current directory on the "U:\" drive
GetFullPathName does not convert the specified file name, lpFileName. If the specified file name exists, you can use GetLongPathName or GetShortPathName to convert to long or short path names, respectively.
If the return value is greater than or equal to the value specified in nBufferLength, you can call the function again with a buffer that is large enough to hold the path. For an example of this case in addition to using zero-length buffer for dynamic allocation, see the Example Code section.

Note  Although the return value in this case is a length that includes the terminating null character, the return value on success does not include the terminating null character in the count.
Relative paths passed to the GetFullPathName function are interpreted as relative to the process's current directory. The current directory state written by the SetCurrentDirectory function is global to the process and can be changed by any thread at any time. Applications should be aware that consecutive calls to the GetFullPathName function with a relative path may produce different results if the current directory changes between the two calls.

To avoid problems caused by inconsistent results, multithreaded applications and shared library code should avoid using relative paths. If a relative path is received, it should be consumed exactly once, either by passing the relative path directly to a function like CreateFile, or by converting it to an absolute path and using the absolute path from that point forward.

In Windows 8 and Windows Server 2012, this function is supported by the following technologies.
*/

pub fn GetFullPathNameW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetFullPathNameW(
    //   [in]  LPCWSTR lpFileName,     // RCX
    //   [in]  DWORD   nBufferLength,  // RDX
    //   [out] LPWSTR  lpBuffer,       // R8
    //   [out] LPWSTR  *lpFilePart     // R9
    // )
    
    let lp_file_name = emu.reg_read(RegisterX86::RCX)?;
    let n_buffer_length = emu.reg_read(RegisterX86::RDX)? as u32;
    let lp_buffer = emu.reg_read(RegisterX86::R8)?;
    let lp_file_part = emu.reg_read(RegisterX86::R9)?;
    
    log::info!("[GetFullPathNameW] lpFileName: 0x{:x}", lp_file_name);
    log::info!("[GetFullPathNameW] nBufferLength: {} wide characters", n_buffer_length);
    log::info!("[GetFullPathNameW] lpBuffer: 0x{:x}", lp_buffer);
    log::info!("[GetFullPathNameW] lpFilePart: 0x{:x}", lp_file_part);
    
    // Read the input filename
    let filename = if lp_file_name != 0 {
        match memory::read_wide_string_from_memory(emu, lp_file_name) {
            Ok(s) => s,
            Err(_) => {
                log::error!("[GetFullPathNameW] Failed to read input filename");
                emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
                return Ok(());
            }
        }
    } else {
        log::error!("[GetFullPathNameW] NULL filename pointer");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
        return Ok(());
    };
    
    log::info!("[GetFullPathNameW] Input filename: '{}'", filename);
    
    // Simple approach: if path starts with drive letter or UNC, consider it already full
    // Otherwise prepend C:\ to make it absolute
    let full_path = if filename.len() >= 2 && filename.chars().nth(1) == Some(':') ||
                       filename.starts_with("\\\\") {
        // Already looks like a full path
        filename
    } else if filename.starts_with("\\") {
        // Absolute path without drive - add C:
        format!("C:{}", filename)
    } else {
        // Relative path - prepend C:\
        format!("C:\\{}", filename)
    };
    
    let full_path_wide_len = full_path.encode_utf16().count() as u32;
    let required_buffer_size = full_path_wide_len + 1; // Include null terminator
    
    // Check if buffer is large enough
    if lp_buffer == 0 || n_buffer_length < required_buffer_size {
        // Return required buffer size (including null terminator)
        log::warn!("[GetFullPathNameW] Buffer too small or NULL: need {} wide characters, got {}", 
                  required_buffer_size, n_buffer_length);
        emu.reg_write(RegisterX86::RAX, required_buffer_size as u64)?;
        return Ok(());
    }
    
    // Write the full path to buffer
    let wide_chars: Vec<u16> = full_path.encode_utf16().collect();
    let mut buffer = Vec::with_capacity(wide_chars.len() * 2);
    for &wchar in &wide_chars {
        buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    
    // Write the wide string
    emu.mem_write(lp_buffer, &buffer)?;
    
    // Write null terminator (2 bytes for wide char)
    emu.mem_write(lp_buffer + buffer.len() as u64, &[0u8, 0u8])?;
    
    // Find the filename part (after the last backslash)
    if lp_file_part != 0 {
        let file_part_offset = if let Some(pos) = full_path.rfind('\\') {
            // Point to character after the last backslash
            (pos + 1) * 2 // Convert to wide char byte offset
        } else {
            // No backslash found, point to start of buffer
            0
        };
        
        let file_part_address = lp_buffer + file_part_offset as u64;
        let file_part_bytes = file_part_address.to_le_bytes();
        emu.mem_write(lp_file_part, &file_part_bytes)?;
        
        log::info!("[GetFullPathNameW] lpFilePart set to 0x{:x} (offset {})", file_part_address, file_part_offset);
    }
    
    log::info!("[GetFullPathNameW] Full path: '{}'", full_path);
    log::warn!("[GetFullPathNameW] Mock implementation - simple path resolution");
    
    // Return the length of the string copied (NOT including null terminator)
    emu.reg_write(RegisterX86::RAX, full_path_wide_len as u64)?;
    
    Ok(())
}