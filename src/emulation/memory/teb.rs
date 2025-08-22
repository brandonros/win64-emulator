use unicorn_engine::{uc_error, Permission, Unicorn};
use super::constants::*;

pub fn setup_teb(emu: &mut Unicorn<'static, ()>) -> Result<(), uc_error> {
    log::info!("  Setting up TEB at 0x{:016x}", TEB_BASE);
    
    // Map TEB memory
    emu.mem_map(TEB_BASE, TEB_SIZE, Permission::READ | Permission::WRITE)?;
    
    // Initialize TEB with zeros
    let teb_data = vec![0u8; TEB_SIZE];
    emu.mem_write(TEB_BASE, &teb_data)?;

    // Set GS base to point to TEB
    emu.reg_write(unicorn_engine::RegisterX86::GS_BASE, TEB_BASE)?;
    
    // Write critical TEB fields for x64
    // Offset 0x08: StackBase (top of stack)
    let stack_top = STACK_BASE + STACK_SIZE as u64;
    emu.mem_write(TEB_BASE + 0x08, &stack_top.to_le_bytes())?;
    
    // Offset 0x10: StackLimit (bottom of stack)
    emu.mem_write(TEB_BASE + 0x10, &STACK_BASE.to_le_bytes())?;
    
    // Offset 0x30: Self pointer (linear address of TEB)
    emu.mem_write(TEB_BASE + 0x30, &TEB_BASE.to_le_bytes())?;
    
    // Offset 0x48: Thread ID (using our mock value)
    let thread_id: u64 = 0x1000;
    emu.mem_write(TEB_BASE + 0x48, &thread_id.to_le_bytes())?;
    
    // Offset 0x40: Process ID (mock value)
    let process_id: u64 = 0x100;
    emu.mem_write(TEB_BASE + 0x40, &process_id.to_le_bytes())?;
    
    // Offset 0x60: PEB pointer
    emu.mem_write(TEB_BASE + 0x60, &PEB_BASE.to_le_bytes())?;
    
    // Offset 0x1480: TlsSlots[64] array - initialize to zeros
    // The array is already zeroed when we initialized the TEB with zeros above,
    // but we'll explicitly document this for clarity
    // TlsSlots is a 64-element array of pointers (8 bytes each on x64)
    // Total size: 64 * 8 = 512 bytes
    log::info!("    TEB.TlsSlots = 0x{:016x} (64 slots initialized)", TEB_BASE + TEB_TLS_SLOTS_OFFSET);
    
    log::info!("    TEB.StackBase = 0x{:016x}", stack_top);
    log::info!("    TEB.StackLimit = 0x{:016x}", STACK_BASE);
    log::info!("    TEB.Self = 0x{:016x}", TEB_BASE);
    log::info!("    TEB.ProcessId = 0x{:x}", process_id);
    log::info!("    TEB.ThreadId = 0x{:x}", thread_id);
    log::info!("    TEB.Peb = 0x{:016x}", PEB_BASE);
    
    Ok(())
}