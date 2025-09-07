use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;

/*
SHGetFolderPathW function (shlobj_core.h)
02/08/2023
Deprecated. Gets the path of a folder identified by a CSIDL value.

Note  As of Windows Vista, this function is merely a wrapper for SHGetKnownFolderPath. The CSIDL value is translated to its associated KNOWNFOLDERID and then SHGetKnownFolderPath is called. New applications should use the known folder system rather than the older CSIDL system, which is supported only for backward compatibility.
 
Syntax
C++

Copy
SHFOLDERAPI SHGetFolderPathW(
  [in]  HWND   hwnd,
  [in]  int    csidl,
  [in]  HANDLE hToken,
  [in]  DWORD  dwFlags,
  [out] LPWSTR pszPath
);
Parameters
[in] hwnd

Type: HWND

Reserved.

[in] csidl

Type: int

A CSIDL value that identifies the folder whose path is to be retrieved. Only real folders are valid. If a virtual folder is specified, this function fails. You can force creation of a folder by combining the folder's CSIDL with CSIDL_FLAG_CREATE.

[in] hToken

Type: HANDLE

An access token that can be used to represent a particular user.

Microsoft Windows 2000 and earlier: Always set this parameter to NULL.

Windows XP and later: This parameter is usually set to NULL, but you might need to assign a non-NULL value to hToken for those folders that can have multiple users but are treated as belonging to a single user. The most commonly used folder of this type is Documents.

The calling process is responsible for correct impersonation when hToken is non-NULL. The calling process must have appropriate security privileges for the particular user, including TOKEN_QUERY and TOKEN_IMPERSONATE, and the user's registry hive must be currently mounted. See Access Control for further discussion of access control issues.

Assigning the hToken parameter a value of -1 indicates the Default User. This enables clients of SHGetFolderPath to find folder locations (such as the Desktop folder) for the Default User. The Default User user profile is duplicated when any new user account is created, and includes special folders such as My Documents and Desktop. Any items added to the Default User folder also appear in any new user account.

[in] dwFlags

Type: DWORD

Flags that specify the path to be returned. This value is used in cases where the folder associated with a KNOWNFOLDERID (or CSIDL) can be moved, renamed, redirected, or roamed across languages by a user or administrator.

The known folder system that underlies SHGetFolderPath allows users or administrators to redirect a known folder to a location that suits their needs. This is achieved by calling IKnownFolderManager::Redirect, which sets the "current" value of the folder associated with the SHGFP_TYPE_CURRENT flag.

The default value of the folder, which is the location of the folder if a user or administrator had not redirected it elsewhere, is retrieved by specifying the SHGFP_TYPE_DEFAULT flag. This value can be used to implement a "restore defaults" feature for a known folder.

For example, the default value (SHGFP_TYPE_DEFAULT) for FOLDERID_Music (CSIDL_MYMUSIC) is "C:\Users\user name\Music". If the folder was redirected, the current value (SHGFP_TYPE_CURRENT) might be "D:\Music". If the folder has not been redirected, then SHGFP_TYPE_DEFAULT and SHGFP_TYPE_CURRENT retrieve the same path.

SHGFP_TYPE_CURRENT
Retrieve the folder's current path.

SHGFP_TYPE_DEFAULT
Retrieve the folder's default path.

[out] pszPath

Type: LPWSTR

A pointer to a null-terminated string of length MAX_PATH which will receive the path. If an error occurs or S_FALSE is returned, this string will be empty. The returned path does not include a trailing backslash. For example, "C:\Users" is returned rather than "C:\Users\".

Return value
Type: HRESULT

If this function succeeds, it returns S_OK. Otherwise, it returns an HRESULT error code.

Remarks
This function is a superset of SHGetSpecialFolderPath.

Only some CSIDL values are supported, including the following:

CSIDL_ADMINTOOLS
CSIDL_APPDATA
CSIDL_COMMON_ADMINTOOLS
CSIDL_COMMON_APPDATA
CSIDL_COMMON_DOCUMENTS
CSIDL_COOKIES
CSIDL_FLAG_CREATE
CSIDL_FLAG_DONT_VERIFY
CSIDL_HISTORY
CSIDL_INTERNET_CACHE
CSIDL_LOCAL_APPDATA
CSIDL_MYPICTURES
CSIDL_PERSONAL
CSIDL_PROGRAM_FILES
CSIDL_PROGRAM_FILES_COMMON
CSIDL_SYSTEM
CSIDL_WINDOWS
Examples
The following code example uses SHGetFolderPath to find or create a folder and then creates a file in it.

C++

Copy
TCHAR szPath[MAX_PATH];

if(SUCCEEDED(SHGetFolderPath(NULL, 
                             CSIDL_PERSONAL|CSIDL_FLAG_CREATE, 
                             NULL, 
                             0, 
                             szPath))) 
{
    PathAppend(szPath, TEXT("New Doc.txt"));
    HANDLE hFile = CreateFile(szPath, ...);
}
 Note

The shlobj_core.h header defines SHGetFolderPath as an alias that automatically selects the ANSI or Unicode version of this function based on the definition of the UNICODE preprocessor constant. Mixing usage of the encoding-neutral alias with code that is not encoding-neutral can lead to mismatches that result in compilation or runtime errors. For more information, see Conventions for Function Prototypes.

Requirements
Requirement	Value
Minimum supported client	Windows 2000 Professional, Windows XP [desktop apps only]
Minimum supported server	Windows 2000 Server [desktop apps only]
Target Platform	Windows
Header	shlobj_core.h (include Shlobj.h, Shlobj_core.h)
Library	Shell32.lib
DLL	Shell32.dll (version 5.0 or later)
See also
IKnownFolder::GetPath
*/

pub fn SHGetFolderPathW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HRESULT SHGetFolderPathW(
    //   [in]  HWND   hwnd,      // RCX
    //   [in]  int    csidl,     // RDX
    //   [in]  HANDLE hToken,    // R8
    //   [in]  DWORD  dwFlags,   // R9
    //   [out] LPWSTR pszPath    // [RSP+0x28]
    // )
    
    let hwnd = emu.reg_read(X86Register::RCX)?;
    let csidl = emu.reg_read(X86Register::RDX)? as i32;
    let h_token = emu.reg_read(X86Register::R8)?;
    let dw_flags = emu.reg_read(X86Register::R9)? as u32;
    
    // Read pszPath from stack (5th parameter)
    let rsp = emu.reg_read(X86Register::RSP)?;
    let mut psz_path_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x28, &mut psz_path_bytes)?;
    let psz_path = u64::from_le_bytes(psz_path_bytes);
    
    log::info!("[SHGetFolderPathW] hwnd: 0x{:x}", hwnd);
    log::info!("[SHGetFolderPathW] csidl: 0x{:x}", csidl);
    log::info!("[SHGetFolderPathW] hToken: 0x{:x}", h_token);
    log::info!("[SHGetFolderPathW] dwFlags: 0x{:x}", dw_flags);
    log::info!("[SHGetFolderPathW] pszPath: 0x{:x}", psz_path);
    
    // HRESULT constants
    const S_OK: u32 = 0x00000000;
    const E_INVALIDARG: u32 = 0x80070057;
    
    // Check for NULL pszPath
    if psz_path == 0 {
        log::error!("[SHGetFolderPathW] NULL pszPath pointer");
        emu.reg_write(X86Register::RAX, E_INVALIDARG as u64)?;
        return Ok(());
    }
    
    // Extract flags and actual CSIDL value
    let create_flag = (csidl & 0x8000) != 0;  // CSIDL_FLAG_CREATE
    let actual_csidl = csidl & 0xFFFF;
    
    if create_flag {
        log::info!("[SHGetFolderPathW] CSIDL_FLAG_CREATE is set");
    }
    
    // Map CSIDL values to folder paths
    let folder_path = match actual_csidl {
        0x0005 => "C:\\Users\\User\\Documents",           // CSIDL_PERSONAL
        0x001a => "C:\\Users\\User\\AppData\\Roaming",    // CSIDL_APPDATA
        0x001c => "C:\\Users\\User\\AppData\\Local",      // CSIDL_LOCAL_APPDATA
        0x0020 => "C:\\Users\\User\\AppData\\Local\\Microsoft\\Windows\\INetCache", // CSIDL_INTERNET_CACHE
        0x0021 => "C:\\Users\\User\\AppData\\Local\\Microsoft\\Windows\\INetCookies", // CSIDL_COOKIES
        0x0022 => "C:\\Users\\User\\AppData\\Local\\Microsoft\\Windows\\History", // CSIDL_HISTORY
        0x0023 => "C:\\ProgramData",                      // CSIDL_COMMON_APPDATA
        0x0024 => "C:\\Windows",                          // CSIDL_WINDOWS
        0x0025 => "C:\\Windows\\System32",                // CSIDL_SYSTEM
        0x0026 => "C:\\Program Files",                    // CSIDL_PROGRAM_FILES
        0x0027 => "C:\\Users\\User\\Pictures",            // CSIDL_MYPICTURES
        0x0028 => "C:\\Users\\User",                      // CSIDL_PROFILE
        0x0029 => "C:\\Windows\\SysWOW64",                // CSIDL_SYSTEMX86
        0x002a => "C:\\Program Files (x86)",              // CSIDL_PROGRAM_FILESX86
        0x002b => "C:\\Program Files\\Common Files",      // CSIDL_PROGRAM_FILES_COMMON
        0x002c => "C:\\Program Files (x86)\\Common Files", // CSIDL_PROGRAM_FILES_COMMONX86
        0x002d => "C:\\ProgramData\\Microsoft\\Windows\\Templates", // CSIDL_COMMON_TEMPLATES
        0x002e => "C:\\Users\\Public\\Documents",         // CSIDL_COMMON_DOCUMENTS
        0x002f => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools", // CSIDL_COMMON_ADMINTOOLS
        0x0030 => "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools", // CSIDL_ADMINTOOLS
        0x0031 => "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts", // CSIDL_CONNECTIONS
        0x0035 => "C:\\Users\\Public\\Music",             // CSIDL_COMMON_MUSIC
        0x0036 => "C:\\Users\\Public\\Pictures",          // CSIDL_COMMON_PICTURES
        0x0037 => "C:\\Users\\Public\\Videos",            // CSIDL_COMMON_VIDEO
        0x0038 => "C:\\Windows\\Resources",               // CSIDL_RESOURCES
        0x0000 => "C:\\Users\\User\\Desktop",             // CSIDL_DESKTOP
        0x0002 => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", // CSIDL_PROGRAMS
        0x0010 => "C:\\Users\\User\\Desktop",             // CSIDL_DESKTOPDIRECTORY
        0x000d => "C:\\Users\\User\\Music",               // CSIDL_MYMUSIC
        0x000e => "C:\\Users\\User\\Videos",              // CSIDL_MYVIDEO
        _ => {
            log::warn!("[SHGetFolderPathW] Unimplemented CSIDL value: 0x{:x}", actual_csidl);
            emu.reg_write(X86Register::RAX, E_INVALIDARG as u64)?;
            return Ok(());
        }
    };
    
    // Write the folder path to pszPath buffer
    memory::write_wide_string_to_memory(emu, psz_path, folder_path)?;
    
    log::info!("[SHGetFolderPathW] Returned folder path: '{}'", folder_path);
    log::warn!("[SHGetFolderPathW] Mock implementation - returned folder: '{}'", folder_path);
    
    // Return S_OK
    emu.reg_write(X86Register::RAX, S_OK as u64)?;
    
    Ok(())
}