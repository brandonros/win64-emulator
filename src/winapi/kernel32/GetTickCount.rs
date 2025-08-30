use unicorn_engine::{Unicorn, RegisterX86};
use std::time::{SystemTime, UNIX_EPOCH};

/*
GetTickCount function (sysinfoapi.h)
07/11/2024
Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.

Syntax
C++

Copy
DWORD GetTickCount();
Return value
The return value is the number of milliseconds that have elapsed since the system was started.

Remarks
The resolution of the GetTickCount function is limited to the resolution of the system timer, which is typically in the range of 10 milliseconds to 16 milliseconds. The resolution of the GetTickCount function is not affected by adjustments made by the GetSystemTimeAdjustment function.

The elapsed time is stored as a DWORD value. Therefore, the time will wrap around to zero if the system is run continuously for 49.7 days. To avoid this problem, use the GetTickCount64 function. Otherwise, check for an overflow condition when comparing times.

If you need a higher resolution timer, use a multimedia timer or a high-resolution timer.

To obtain the time elapsed since the computer was started, retrieve the System Up Time counter in the performance data in the registry key HKEY_PERFORMANCE_DATA. The value returned is an 8-byte value. For more information, see Performance Counters.

To obtain the time the system has spent in the working state since it was started, use the QueryUnbiasedInterruptTime function.
*/

pub fn GetTickCount(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD GetTickCount();
    // No parameters - returns tick count in RAX
    
    // For emulation, we'll use a simulated tick count based on current time
    // In a real implementation, this would track elapsed time since system boot
    
    // Get current time in milliseconds since UNIX epoch
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    // Convert to milliseconds and truncate to 32 bits (DWORD)
    // This will wrap around every ~49.7 days as per the API specification
    let millis = now.as_millis() as u64;
    let tick_count = (millis & 0xFFFFFFFF) as u32;
    
    log::info!("[GetTickCount] Returning tick count: {} ms (0x{:x})", tick_count, tick_count);
    
    // Handle wrap-around warning if close to overflow
    if tick_count > 0xFFFFF000 {
        log::warn!("[GetTickCount] Tick count approaching 32-bit overflow (49.7 days)");
    }
    
    log::warn!("[GetTickCount] Mock implementation - using current time as tick source");
    
    // Return the tick count in RAX (32-bit value, zero-extended to 64 bits)
    emu.reg_write(RegisterX86::RAX, tick_count as u64)?;
    
    Ok(())
}