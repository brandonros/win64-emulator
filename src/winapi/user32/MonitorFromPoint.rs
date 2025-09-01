use unicorn_engine::{Unicorn, RegisterX86};
use std::sync::atomic::{AtomicU64, Ordering};

// Monitor flags
const MONITOR_DEFAULTTONULL: u32 = 0x00000000;
const MONITOR_DEFAULTTOPRIMARY: u32 = 0x00000001;
const MONITOR_DEFAULTTONEAREST: u32 = 0x00000002;

// Primary monitor handle
const PRIMARY_MONITOR_HANDLE: u64 = 0x10001;

// Monitor handle counter for non-primary monitors
static MONITOR_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(0x10002);

pub fn MonitorFromPoint(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HMONITOR MonitorFromPoint(
    //   [in] POINT pt,      // RCX (x and y packed into 64-bit: low 32 bits = x, high 32 bits = y)
    //   [in] DWORD dwFlags  // RDX
    // )
    
    let point = emu.reg_read(RegisterX86::RCX)?;
    let flags = emu.reg_read(RegisterX86::RDX)? as u32;
    
    // Extract x and y from POINT structure (two 32-bit LONG values)
    let x = (point & 0xFFFFFFFF) as i32;
    let y = ((point >> 32) & 0xFFFFFFFF) as i32;
    
    log::info!("[MonitorFromPoint] Point: ({}, {}), Flags: 0x{:x}", x, y, flags);
    
    // Simple mock: assume primary monitor covers 0,0 to 1920,1080
    let in_primary_monitor = x >= 0 && x < 1920 && y >= 0 && y < 1080;
    
    let hmonitor = if in_primary_monitor {
        log::info!("[MonitorFromPoint] Point is within primary monitor");
        PRIMARY_MONITOR_HANDLE
    } else {
        // Point is outside any monitor
        match flags {
            MONITOR_DEFAULTTONULL => {
                log::info!("[MonitorFromPoint] Point outside monitors, returning NULL (MONITOR_DEFAULTTONULL)");
                0
            }
            MONITOR_DEFAULTTOPRIMARY => {
                log::info!("[MonitorFromPoint] Point outside monitors, returning primary monitor (MONITOR_DEFAULTTOPRIMARY)");
                PRIMARY_MONITOR_HANDLE
            }
            MONITOR_DEFAULTTONEAREST => {
                log::info!("[MonitorFromPoint] Point outside monitors, returning nearest monitor (MONITOR_DEFAULTTONEAREST)");
                PRIMARY_MONITOR_HANDLE // For simplicity, return primary as nearest
            }
            _ => {
                log::warn!("[MonitorFromPoint] Unknown flags: 0x{:x}, defaulting to NULL", flags);
                0
            }
        }
    };
    
    log::info!("[MonitorFromPoint] Returning HMONITOR: 0x{:x}", hmonitor);
    
    // Return the monitor handle
    emu.reg_write(RegisterX86::RAX, hmonitor)?;
    
    Ok(())
}