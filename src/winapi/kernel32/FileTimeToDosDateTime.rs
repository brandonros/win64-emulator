/*
FileTimeToDosDateTime function (winbase.h)
02/22/2024
Converts a file time to MS-DOS date and time values.

Syntax
C++

Copy
BOOL FileTimeToDosDateTime(
  [in]  const FILETIME *lpFileTime,
  [out] LPWORD         lpFatDate,
  [out] LPWORD         lpFatTime
);
Parameters
[in] lpFileTime

A pointer to a FILETIME structure containing the file time to convert to MS-DOS date and time format.

[out] lpFatDate

A pointer to a variable to receive the MS-DOS date. The date is a packed value with the following format.

Bits	Description
0–4	Day of the month (1–31)
5–8	Month (1 = January, 2 = February, etc.)
9-15	Year offset from 1980 (add 1980 to get actual year)
[out] lpFatTime

A pointer to a variable to receive the MS-DOS time. The time is a packed value with the following format.

Bits	Description
0–4	Second divided by 2
5–10	Minute (0–59)
11–15	Hour (0–23 on a 24-hour clock)
Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use windows_sys::Win32::Foundation::FILETIME;
use crate::emulation::memory;

pub fn FileTimeToDosDateTime(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let lp_file_time = emu.reg_read(X86Register::RCX)?;
    let lp_fat_date = emu.reg_read(X86Register::RDX)?;
    let lp_fat_time = emu.reg_read(X86Register::R8)?;
    
    // Read the FILETIME structure
    let file_time: FILETIME = memory::read_struct(emu, lp_file_time)?;
    
    // Mock DOS date: January 1, 2020
    // Year: 2020 - 1980 = 40 (bits 9-15)
    // Month: 1 (bits 5-8)  
    // Day: 1 (bits 0-4)
    let dos_date: u16 = (40 << 9) | (1 << 5) | 1;
    
    // Mock DOS time: 12:00:00
    // Hour: 12 (bits 11-15)
    // Minute: 0 (bits 5-10)
    // Second/2: 0 (bits 0-4)
    let dos_time: u16 = (12 << 11) | (0 << 5) | 0;
    
    // Write the DOS date and time
    emu.mem_write(lp_fat_date, &dos_date.to_le_bytes())?;
    emu.mem_write(lp_fat_time, &dos_time.to_le_bytes())?;
    
    log::info!("[FileTimeToDosDateTime] FileTime ptr: 0x{:x} (dwLowDateTime: 0x{:x}, dwHighDateTime: 0x{:x}), DOS Date: 0x{:04x}, DOS Time: 0x{:04x}, returning 1 (success)",
              lp_file_time, file_time.dwLowDateTime, file_time.dwHighDateTime, dos_date, dos_time);
    
    // Return success
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}