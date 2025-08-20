use unicorn_engine::{uc_error, Permission, Unicorn};
use super::constants::*;

pub fn setup_peb(emu: &mut Unicorn<'static, ()>, image_base: u64) -> Result<(), uc_error> {
    log::info!("  Setting up PEB at 0x{:016x}", PEB_BASE);
    
    // Map PEB memory
    emu.mem_map(PEB_BASE, PEB_SIZE, Permission::READ | Permission::WRITE)?;
    
    // Initialize PEB with zeros
    let peb_data = vec![0u8; PEB_SIZE];
    emu.mem_write(PEB_BASE, &peb_data)?;
    
    // Write critical PEB fields for x64
    // Offset 0x10: ImageBaseAddress
    emu.mem_write(PEB_BASE + 0x10, &image_base.to_le_bytes())?;
    
    // Offset 0x03: BeingDebugged (set to 0 for not being debugged)
    emu.mem_write(PEB_BASE + 0x02, &[0u8])?;
    
    // Offset 0x0C: Ldr (we'll leave this null for now)
    // Offset 0x18: ProcessHeap (point to our heap)
    emu.mem_write(PEB_BASE + 0x18, &HEAP_BASE.to_le_bytes())?;
    
    log::info!("    PEB.ImageBaseAddress = 0x{:016x}", image_base);
    log::info!("    PEB.ProcessHeap = 0x{:016x}", HEAP_BASE);
    log::info!("    PEB.BeingDebugged = 0");
    
    Ok(())
}