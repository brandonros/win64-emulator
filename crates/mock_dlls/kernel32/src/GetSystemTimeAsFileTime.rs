#![allow(non_snake_case)]

use windows_sys::Win32::Foundation::FILETIME;
use std::time::{SystemTime, UNIX_EPOCH};

// GetSystemTimeAsFileTime - Retrieves the current system date and time in FILETIME format
#[unsafe(no_mangle)]
pub extern "system" fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut FILETIME) {
    log::info!("[GetSystemTimeAsFileTime] lpSystemTimeAsFileTime: {:p}", lpSystemTimeAsFileTime);
    
    if !lpSystemTimeAsFileTime.is_null() {
        // Get current system time
        let now = SystemTime::now();
        let duration_since_epoch = now.duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0));
        
        // Convert to Windows FILETIME format
        // FILETIME represents the number of 100-nanosecond intervals since January 1, 1601 (UTC)
        // Unix epoch is January 1, 1970, so we need to add the difference
        const UNIX_TO_FILETIME_OFFSET: u64 = 116444736000000000; // 100ns intervals between 1601 and 1970
        
        let filetime_value = duration_since_epoch.as_nanos() as u64 / 100 + UNIX_TO_FILETIME_OFFSET;
        
        unsafe {
            (*lpSystemTimeAsFileTime).dwLowDateTime = (filetime_value & 0xFFFFFFFF) as u32;
            (*lpSystemTimeAsFileTime).dwHighDateTime = (filetime_value >> 32) as u32;
        }
        
        log::info!(
            "[GetSystemTimeAsFileTime] Set FILETIME: low=0x{:08x}, high=0x{:08x}", 
            unsafe { (*lpSystemTimeAsFileTime).dwLowDateTime },
            unsafe { (*lpSystemTimeAsFileTime).dwHighDateTime }
        );
    }
}