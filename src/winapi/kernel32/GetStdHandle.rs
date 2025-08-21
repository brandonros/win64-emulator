use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetStdHandle(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the nStdHandle parameter from RCX register
    let n_std_handle = emu.reg_read(RegisterX86::RCX)? as u32;
    
    // Define the standard handle constants
    const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;  // (DWORD)-10
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5; // (DWORD)-11
    const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;  // (DWORD)-12
    
    // Return a mock handle value based on the requested handle type
    let handle = match n_std_handle {
        STD_INPUT_HANDLE => {
            log::info!("[GetStdHandle] Returning STD_INPUT_HANDLE");
            0x10 // Mock handle for stdin
        },
        STD_OUTPUT_HANDLE => {
            log::info!("[GetStdHandle] Returning STD_OUTPUT_HANDLE");
            0x14 // Mock handle for stdout
        },
        STD_ERROR_HANDLE => {
            log::info!("[GetStdHandle] Returning STD_ERROR_HANDLE");
            0x18 // Mock handle for stderr
        },
        _ => {
            log::warn!("[GetStdHandle] Unknown handle type: 0x{:x}", n_std_handle);
            0xFFFFFFFFFFFFFFFF // INVALID_HANDLE_VALUE
        }
    };
    
    // Set the return value in RAX register
    emu.reg_write(RegisterX86::RAX, handle)?;
    
    Ok(())
}