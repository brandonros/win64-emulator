/*
GetFileVersionInfoSizeA function (winver.h)
11/19/2024
Determines whether the operating system can retrieve version information for a specified file. If version information is available, GetFileVersionInfoSize returns the size, in bytes, of that information.

Syntax
C++

Copy
DWORD GetFileVersionInfoSizeA(
  [in]            LPCSTR  lptstrFilename,
  [out, optional] LPDWORD lpdwHandle
);
Parameters
[in] lptstrFilename

Type: LPCTSTR

The name of the file of interest. The function uses the search sequence specified by the LoadLibrary function.

[out, optional] lpdwHandle

Type: LPDWORD

A pointer to a variable that the function sets to zero.

Return value
Type: DWORD

If the function succeeds, the return value is the size, in bytes, of the file's version information.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
Call the GetFileVersionInfoSize function before calling the GetFileVersionInfo function. The size returned by GetFileVersionInfoSize indicates the buffer size required for the version information returned by GetFileVersionInfo.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use crate::emulation::vfs::VIRTUAL_FS;
use crate::winapi;
use windows_sys::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;

pub fn GetFileVersionInfoSizeA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetFileVersionInfoSizeA(
    //   LPCSTR  lptstrFilename,  // RCX
    //   LPDWORD lpdwHandle        // RDX
    // )
    
    let filename_ptr = emu.reg_read(RegisterX86::RCX)?;
    let handle_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    // Read the filename
    let filename = if filename_ptr != 0 {
        memory::read_string_from_memory(emu, filename_ptr)?
    } else {
        String::from("")
    };
    
    log::info!(
        "[GetFileVersionInfoSizeA] Filename: \"{}\", HandlePtr: 0x{:x}",
        filename, handle_ptr
    );
    
    // Set the handle to zero if provided
    if handle_ptr != 0 {
        let zero: u32 = 0;
        emu.mem_write(handle_ptr, &zero.to_le_bytes())?;
        log::debug!("[GetFileVersionInfoSizeA] Set handle to 0");
    }
    
    // Check if file exists in VFS
    let file_exists = if !filename.is_empty() {
        let vfs = VIRTUAL_FS.read().unwrap();
        vfs.file_exists(&filename)
    } else {
        false
    };
    
    // Calculate mock version info size
    // VS_FIXEDFILEINFO structure + extra space for version strings and other data
    let fixed_file_info_size = std::mem::size_of::<VS_FIXEDFILEINFO>() as u32;
    // Add space for version strings (CompanyName, FileDescription, FileVersion, etc.)
    // Typically these take a few hundred bytes
    const VERSION_STRINGS_SIZE: u32 = 512;
    let mock_version_info_size = fixed_file_info_size + VERSION_STRINGS_SIZE;
    
    if filename.is_empty() {
        log::warn!("[GetFileVersionInfoSizeA] Invalid filename (null or empty), returning 0");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(RegisterX86::RAX, 0)?;
    } else if !file_exists {
        log::warn!("[GetFileVersionInfoSizeA] File not found in VFS: \"{}\"", filename);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND)?;
        emu.reg_write(RegisterX86::RAX, 0)?;
    } else {
        log::info!("[GetFileVersionInfoSizeA] File \"{}\" exists in VFS, returning version info size: {} bytes (VS_FIXEDFILEINFO: {} + strings: {})", 
            filename, mock_version_info_size, fixed_file_info_size, VERSION_STRINGS_SIZE);
        emu.reg_write(RegisterX86::RAX, mock_version_info_size as u64)?;
    }
    
    Ok(())
}