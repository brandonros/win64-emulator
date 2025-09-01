use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::Foundation::FILETIME;
use crate::emulation::memory;

pub fn FileTimeToLocalFileTime(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let lp_file_time = emu.reg_read(RegisterX86::RCX)?;
    let lp_local_file_time = emu.reg_read(RegisterX86::RDX)?;
    
    // Read the UTC FILETIME structure
    let utc_file_time: FILETIME = memory::read_struct(emu, lp_file_time)?;
    
    // For now, just copy UTC time to local time (no timezone conversion in mock)
    // In a real implementation, you would apply timezone offset here
    let local_file_time = utc_file_time;
    
    // Write the local FILETIME structure
    memory::write_struct(emu, lp_local_file_time, &local_file_time)?;
    
    log::info!("[FileTimeToLocalFileTime] UTC FileTime ptr: 0x{:x} (dwLowDateTime: 0x{:x}, dwHighDateTime: 0x{:x}), Local FileTime ptr: 0x{:x}, returning 1 (success)", 
              lp_file_time, utc_file_time.dwLowDateTime, utc_file_time.dwHighDateTime, lp_local_file_time);
    
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}