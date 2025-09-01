use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

pub fn GetSystemMetrics(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get the metric index from ECX register
    let index = emu.reg_read(RegisterX86::RCX)? as i32;
    
    let value = match index {
        0 => 1920,  // SM_CXSCREEN - width of primary display
        1 => 1080,  // SM_CYSCREEN - height of primary display
        11 => 32,   // SM_CXICON - width of large icon
        12 => 32,   // SM_CYICON - height of large icon
        49 => 16,   // SM_CXSMICON - width of small icon
        50 => 16,   // SM_CYSMICON - height of small icon
        19 => 1,    // SM_MOUSEPRESENT - mouse is installed
        80 => 1,    // SM_CMONITORS - number of monitors
        42 => 1,    // SM_DBCSENABLED - DBCS support (Double-Byte Character Set)
        74 => 1,    // SM_MIDEASTENABLED - Middle East language support (0 = not enabled)
        82 => 1,    // SM_IMMENABLED - IME support for East Asian input
        4096 => 0,  // SM_REMOTESESSION
        _ => {
            log::warn!("[GetSystemMetrics] Unhandled metric index: {}", index);
            panic!("[GetSystemMetrics] Unimplemented system metric: {}", index);
        }
    };
    
    log::debug!("[GetSystemMetrics] Index: {} = {}", index, value);
    
    // Return value in EAX
    emu.reg_write(RegisterX86::RAX, value as u64)?;
    
    Ok(())
}