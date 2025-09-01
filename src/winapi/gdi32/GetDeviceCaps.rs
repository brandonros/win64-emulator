use unicorn_engine::{Unicorn, RegisterX86};

const HORZRES: i32 = 8;
const VERTRES: i32 = 10;
const BITSPIXEL: i32 = 12;
const PLANES: i32 = 14;
const LOGPIXELSX: i32 = 88;
const LOGPIXELSY: i32 = 90;

pub fn GetDeviceCaps(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let hdc = emu.reg_read(RegisterX86::RCX)?;
    let index = emu.reg_read(RegisterX86::RDX)? as i32;
    
    let result = match index {
        HORZRES => 1920,
        VERTRES => 1080,
        BITSPIXEL => 32,
        PLANES => 1,
        LOGPIXELSX => 96,
        LOGPIXELSY => 96,
        _ => {
            log::info!("[GetDeviceCaps] HDC: 0x{:x}, Index: {} (unhandled), returning 0", hdc, index);
            0
        }
    };
    
    if result != 0 {
        log::info!("[GetDeviceCaps] HDC: 0x{:x}, Index: {}, returning: {}", hdc, index, result);
    }
    
    emu.reg_write(RegisterX86::RAX, result as u64)?;
    
    Ok(())
}