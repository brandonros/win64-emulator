use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;
use windows_sys::Win32::Foundation::FILETIME;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::emulation::memory;

pub fn GetSystemTimeAsFileTime(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the pointer to FILETIME structure from RCX register
    let filetime_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[GetSystemTimeAsFileTime] filetime_ptr: 0x{:x}", filetime_ptr);
    
    if filetime_ptr > 0 {
        // Get current system time
        let now = SystemTime::now();
        let duration_since_epoch = now.duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0));
        
        // Convert to Windows FILETIME format
        // FILETIME represents the number of 100-nanosecond intervals since January 1, 1601 (UTC)
        // Unix epoch is January 1, 1970, so we need to add the difference
        const UNIX_TO_FILETIME_OFFSET: u64 = 116444736000000000; // 100ns intervals between 1601 and 1970
        
        let filetime_value = duration_since_epoch.as_nanos() as u64 / 100 + UNIX_TO_FILETIME_OFFSET;
        
        let mock_filetime = FILETIME {
            dwLowDateTime: (filetime_value & 0xFFFFFFFF) as u32,
            dwHighDateTime: (filetime_value >> 32) as u32,
        };
        
        memory::write_struct(emu, filetime_ptr, &mock_filetime)?;
    }
    
    Ok(())
}
