/*
GetFileVersionInfoA function (winver.h)
11/19/2024
Retrieves version information for the specified file.

Syntax
C++

Copy
BOOL GetFileVersionInfoA(
  [in]  LPCSTR lptstrFilename,
        DWORD  dwHandle,
  [in]  DWORD  dwLen,
  [out] LPVOID lpData
);
Parameters
[in] lptstrFilename

Type: LPCTSTR

The name of the file. If a full path is not specified, the function uses the search sequence specified by the LoadLibrary function.

dwHandle

Type: DWORD

This parameter is ignored.

[in] dwLen

Type: DWORD

The size, in bytes, of the buffer pointed to by the lpData parameter.

Call the GetFileVersionInfoSize function first to determine the size, in bytes, of a file's version information. The dwLen member should be equal to or greater than that value.

If the buffer pointed to by lpData is not large enough, the function truncates the file's version information to the size of the buffer.

[out] lpData

Type: LPVOID

Pointer to a buffer that receives the file-version information.

You can use this value in a subsequent call to the VerQueryValue function to retrieve data from the buffer.

Return value
Type: BOOL

If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
File version info has fixed and non-fixed part. The fixed part contains information like version number. The non-fixed part contains things like strings. In the past GetFileVersionInfo was taking version information from the binary (exe/dll). Currently, it is querying fixed version from language neutral file (exe/dll) and the non-fixed part from mui file, merges them and returns to the user. If the given binary does not have a mui file then behavior is as in previous version.

Call the GetFileVersionInfoSize function before calling the GetFileVersionInfo function. To retrieve information from the file-version information buffer, use the VerQueryValue function.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use crate::winapi;
use windows_sys::Win32::Storage::FileSystem::VS_FIXEDFILEINFO;

// Simple VS_VERSIONINFO structure that just contains the VS_FIXEDFILEINFO
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct VS_VERSIONINFO {
    length: u16,
    value_length: u16,
    type_: u16,
    // key "VS_VERSION_INFO\0" follows as wide string
    // padding to align
    // VS_FIXEDFILEINFO value follows
}

fn write_version_info(emu: &mut Unicorn<()>, address: u64, filename: &str) -> Result<(), unicorn_engine::uc_error> {
    // VS_VERSION_INFO header
    let header = VS_VERSIONINFO {
        length: 348,  // Total size of the version resource
        value_length: std::mem::size_of::<VS_FIXEDFILEINFO>() as u16,
        type_: 0,  // Binary data
    };
    
    // Write header
    memory::write_struct(emu, address, &header)?;
    let mut offset = address + 6;
    
    // Write "VS_VERSION_INFO\0" as wide string
    let key = "VS_VERSION_INFO\0";
    memory::write_wide_string_to_memory(emu, offset, key)?;
    offset += (key.len() * 2) as u64;
    
    // Align to 32-bit boundary
    while offset % 4 != 0 {
        emu.mem_write(offset, &[0u8])?;
        offset += 1;
    }
    
    // Create VS_FIXEDFILEINFO based on the filename
    let fixed_info = match filename {
        "comctl32.dll" => VS_FIXEDFILEINFO {
            dwSignature: 0xFEEF04BD,
            dwStrucVersion: 0x00010000,
            dwFileVersionMS: 0x0006000A,     // 6.10
            dwFileVersionLS: 0x585D11BD,     // 22621.4541
            dwProductVersionMS: 0x000A0000,  // 10.0
            dwProductVersionLS: 0x585D11BD,  // 22621.4541
            dwFileFlagsMask: 0x0000003F,
            dwFileFlags: 0x00000000,
            dwFileOS: 0x00040004,            // VOS_NT_WINDOWS32
            dwFileType: 0x00000002,          // VFT_DLL
            dwFileSubtype: 0x00000000,
            dwFileDateMS: 0x00000000,
            dwFileDateLS: 0x00000000,
        },
        _ => {
            // Default version info for unknown files
            VS_FIXEDFILEINFO {
                dwSignature: 0xFEEF04BD,
                dwStrucVersion: 0x00010000,
                dwFileVersionMS: 0x00010000,     // 1.0
                dwFileVersionLS: 0x00000000,     // 0.0
                dwProductVersionMS: 0x00010000,  // 1.0
                dwProductVersionLS: 0x00000000,  // 0.0
                dwFileFlagsMask: 0x0000003F,
                dwFileFlags: 0x00000000,
                dwFileOS: 0x00040004,            // VOS_NT_WINDOWS32
                dwFileType: 0x00000001,          // VFT_APP (application)
                dwFileSubtype: 0x00000000,
                dwFileDateMS: 0x00000000,
                dwFileDateLS: 0x00000000,
            }
        }
    };
    
    // Write VS_FIXEDFILEINFO
    memory::write_struct(emu, offset, &fixed_info)?;
    
    Ok(())
}

pub fn GetFileVersionInfoA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL GetFileVersionInfoA(
    //   LPCSTR lptstrFilename,  // RCX
    //   DWORD  dwHandle,        // RDX (ignored)
    //   DWORD  dwLen,           // R8
    //   LPVOID lpData           // R9
    // )
    
    let filename_ptr = emu.reg_read(RegisterX86::RCX)?;
    let _handle = emu.reg_read(RegisterX86::RDX)?; // Ignored per documentation
    let buffer_len = emu.reg_read(RegisterX86::R8)? as u32;
    let data_ptr = emu.reg_read(RegisterX86::R9)?;
    
    // Read the filename
    let filename = if filename_ptr != 0 {
        memory::read_string_from_memory(emu, filename_ptr)?
    } else {
        String::from("unknown")
    };
    
    log::info!(
        "[GetFileVersionInfoA] Filename: \"{}\", Handle: 0x{:x}, BufferLen: 0x{:x}, DataPtr: 0x{:x}",
        filename, _handle, buffer_len, data_ptr
    );
    
    // Check if we have enough buffer space
    const MIN_VERSION_SIZE: u32 = 348;  // Minimum size for VS_VERSIONINFO + VS_FIXEDFILEINFO
    if buffer_len < MIN_VERSION_SIZE {
        log::warn!("[GetFileVersionInfoA] Buffer too small: {} < {}", buffer_len, MIN_VERSION_SIZE);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER)?;
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Extract just the filename from the path if needed
    let filename_only = filename.split('\\').last().unwrap_or(&filename);
    
    // Write version info for the file
    write_version_info(emu, data_ptr, filename_only)?;
    
    log::info!("[GetFileVersionInfoA] Successfully wrote version info for {}", filename_only);
    
    // Return TRUE for success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}