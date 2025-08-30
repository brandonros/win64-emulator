use unicorn_engine::{Unicorn, RegisterX86};

/*
GetVersion function (sysinfoapi.h)
02/22/2024
GetVersion may be altered or unavailable for releases after Windows 8.1. Instead, use the Version Helper functions. For Windows 10 apps, please see Targeting your applications for Windows.

With the release of Windows 8.1, the behavior of the GetVersion API has changed in the value it will return for the operating system version. The value returned by the GetVersion function now depends on how the application is manifested.

Applications not manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version value (6.2). Once an application is manifested for a given operating system version, GetVersion will always return the version that the application is manifested for in future releases. To manifest your applications for Windows 8.1 or Windows 10, refer to Targeting your application for Windows.

Syntax
C++

Copy
NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion();
Return value
If the function succeeds, the return value includes the major and minor version numbers of the operating system in the low-order word, and information about the operating system platform in the high-order word.

For all platforms, the low-order word contains the version number of the operating system. The low-order byte of this word specifies the major version number, in hexadecimal notation. The high-order byte specifies the minor version (revision) number, in hexadecimal notation. The high-order bit is zero, the next 7 bits represent the build number, and the low-order byte is 5.

Remarks
The GetVersionEx function was developed because many existing applications err when examining the packed DWORD value returned by GetVersion, transposing the major and minor version numbers. GetVersionEx forces applications to explicitly examine each element of version information. VerifyVersionInfo eliminates further potential for error by comparing the required system version with the current system version for you.

Examples
The following code fragment illustrates how to extract information from the GetVersion return value: OSVERSIONINFOEX

C++

Copy
#include <windows.h>
#include <stdio.h>

void main()
{
    DWORD dwVersion = 0; 
    DWORD dwMajorVersion = 0;
    DWORD dwMinorVersion = 0; 
    DWORD dwBuild = 0;

    dwVersion = GetVersion();
 
    // Get the Windows version.

    dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

    // Get the build number.

    if (dwVersion < 0x80000000)              
        dwBuild = (DWORD)(HIWORD(dwVersion));

    printf("Version is %d.%d (%d)\n", 
                dwMajorVersion,
                dwMinorVersion,
                dwBuild);
}
*/

pub fn GetVersion(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetVersion();
    // No parameters - returns version info in RAX
    
    log::info!("[GetVersion] Returning Windows version information");
    
    // Return Windows 10 version information (10.0)
    // Format: Low word = version (major.minor), High word = build number
    // 
    // Version format:
    // - Low byte of low word: Major version (10 = 0x0A)
    // - High byte of low word: Minor version (0 = 0x00)
    // - High word: Build number (19041 = 0x4A51 for Windows 10 20H1)
    
    let major_version: u8 = 10;     // Windows 10
    let minor_version: u8 = 0;      // .0
    let build_number: u16 = 19041;  // Build 19041 (Windows 10 20H1)
    
    // Pack into DWORD format
    // Low word: minor_version (high byte) | major_version (low byte)
    let version_word = ((minor_version as u16) << 8) | (major_version as u16);
    
    // High word: build number
    let version_dword = ((build_number as u32) << 16) | (version_word as u32);
    
    log::info!("[GetVersion] Version: {}.{} Build: {}", major_version, minor_version, build_number);
    log::info!("[GetVersion] Packed DWORD: 0x{:08x}", version_dword);
    log::warn!("[GetVersion] Mock implementation - returned Windows 10.0 Build 19041");
    
    // Return the packed version information
    emu.reg_write(RegisterX86::RAX, version_dword as u64)?;
    
    Ok(())
}