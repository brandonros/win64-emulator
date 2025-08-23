use unicorn_engine::{uc_error, RegisterX86, Unicorn};
use crate::{emulation::hooks, pe::{LoadedPE, constants}};
use super::memory::STACK_BASE;

pub fn setup_cpu_state(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n🖥️  Setting up CPU state:");
    
    // Set entry point
    emu.reg_write(RegisterX86::RIP, pe.entry_point())?;
    log::info!("  RIP: 0x{:016x}", pe.entry_point());
    
    // Set stack pointer
    let stack_pointer = STACK_BASE + 0x100000 as u64;
    emu.reg_write(RegisterX86::RSP, stack_pointer)?;
    log::info!("  RSP: 0x{:016x}", stack_pointer);
    
    // Set up basic registers (Windows x64 ABI)
    emu.reg_write(RegisterX86::RBP, STACK_BASE + 0x100000 as u64 + 0x1000)?;
    
    // Clear other registers
    for &reg in &[RegisterX86::RAX, RegisterX86::RBX, RegisterX86::RCX, 
                  RegisterX86::RDX, RegisterX86::RSI, RegisterX86::RDI] {
        emu.reg_write(reg, 0)?;
    }
    
    // Set up GS base to point to TEB for x64 Windows compatibility
    // GS_BASE register points to TEB
    //emu.reg_write(RegisterX86::GS_BASE, TEB_BASE)?;
    //log::info!("  GS_BASE: 0x{:016x} (TEB)", TEB_BASE);
    
    Ok(())
}

pub fn setup_dll_cpu_state(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE, reason: u32) -> Result<(), uc_error> {
    log::info!("\n🖥️  Setting up CPU state for DLL:");
    
    // Set entry point (DllMain)
    emu.reg_write(RegisterX86::RIP, pe.entry_point())?;
    log::info!("  RIP: 0x{:016x} (DllMain)", pe.entry_point());
    
    // Set stack pointer
    let stack_pointer = STACK_BASE + 0x100000 as u64;
    emu.reg_write(RegisterX86::RSP, stack_pointer)?;
    log::info!("  RSP: 0x{:016x}", stack_pointer);
    
    // Set up DllMain parameters (Windows x64 ABI)
    // BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    // RCX = hinstDLL (module base)
    // RDX = fdwReason (DLL_PROCESS_ATTACH, etc.)
    // R8 = lpReserved (NULL for dynamic load)
    emu.reg_write(RegisterX86::RCX, pe.image_base())?;  // hinstDLL
    emu.reg_write(RegisterX86::RDX, reason as u64)?;     // fdwReason
    emu.reg_write(RegisterX86::R8, 0)?;                  // lpReserved (NULL)
    
    log::info!("  RCX (hinstDLL): 0x{:016x}", pe.image_base());
    log::info!("  RDX (fdwReason): {} ({})", reason, match reason {
        constants::DLL_PROCESS_ATTACH => "DLL_PROCESS_ATTACH",
        constants::DLL_THREAD_ATTACH => "DLL_THREAD_ATTACH",
        constants::DLL_THREAD_DETACH => "DLL_THREAD_DETACH",
        constants::DLL_PROCESS_DETACH => "DLL_PROCESS_DETACH",
        _ => "UNKNOWN"
    });
    log::info!("  R8 (lpReserved): 0x0000000000000000");
    
    // Set up return address on stack (simulate being called)
    let return_addr = 0x7FF000000000u64; // Fake return address
    emu.mem_write(stack_pointer - 8, &return_addr.to_le_bytes())?;
    emu.reg_write(RegisterX86::RSP, stack_pointer - 8)?;
    
    // Set up basic registers
    emu.reg_write(RegisterX86::RBP, STACK_BASE + 0x100000 as u64 + 0x1000)?;
    
    // Clear other registers
    for &reg in &[RegisterX86::RAX, RegisterX86::RBX, 
                  RegisterX86::RSI, RegisterX86::RDI, RegisterX86::R9] {
        emu.reg_write(reg, 0)?;
    }
    
    Ok(())
}

pub fn dump_cpu_state(emu: &mut Unicorn<'static, ()>) -> Result<(), uc_error> {
    log::info!("\n📊 CPU State:");
    
    let registers = [
        ("RIP", RegisterX86::RIP),
        ("RSP", RegisterX86::RSP),
        ("RBP", RegisterX86::RBP),
        ("RAX", RegisterX86::RAX),
        ("RBX", RegisterX86::RBX),
        ("RCX", RegisterX86::RCX),
        ("RDX", RegisterX86::RDX),
        ("RSI", RegisterX86::RSI),
        ("RDI", RegisterX86::RDI),
        ("R8",  RegisterX86::R8),
        ("R9",  RegisterX86::R9),
        ("R10", RegisterX86::R10),
        ("R11", RegisterX86::R11),
        ("R12", RegisterX86::R12),
        ("R13", RegisterX86::R13),
        ("R14", RegisterX86::R14),
        ("R15", RegisterX86::R15),
    ];
    
    // log registers
    for (name, reg) in registers {
        let value = emu.reg_read(reg)?;
        log::info!("  {}: 0x{:016x}", name, value);
    }

    // RFLAGS (super useful for debugging conditionals and exceptions)
    let rflags = emu.reg_read(RegisterX86::RFLAGS)?;
    log::info!("  RFLAGS: 0x{:016x} [CF:{} PF:{} ZF:{} SF:{} OF:{} DF:{}]",
        rflags,
        (rflags & 0x1) != 0,        // Carry Flag
        (rflags & 0x4) != 0,        // Parity Flag  
        (rflags & 0x40) != 0,       // Zero Flag
        (rflags & 0x80) != 0,       // Sign Flag
        (rflags & 0x800) != 0,      // Overflow Flag
        (rflags & 0x400) != 0,      // Direction Flag
    );
    
    // Segment registers (useful for TLS, exceptions, etc.)
    let fs = emu.reg_read(RegisterX86::FS)?;
    let gs = emu.reg_read(RegisterX86::GS)?;
    if fs != 0 || gs != 0 {
        log::info!("  FS: 0x{:016x}  GS: 0x{:016x}", fs, gs);
    }
    
    // Stack preview (top few values)
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    log::info!("  Stack preview:");
    for i in 0..4 {
        let mut bytes = vec![0u8; 8];
        if emu.mem_read(rsp + i*8, &mut bytes).is_ok() {
            let value = u64::from_le_bytes(bytes.try_into().unwrap());
            log::info!("    [RSP+0x{:02x}]: 0x{:016x}", i*8, value);
        }
    }
    
    // Show some memory around RIP
    let count = hooks::get_count();
    let rip = emu.reg_read(RegisterX86::RIP)?;
    let mut code = vec![0u8; 16];
    if emu.mem_read(rip, &mut code).is_ok() {
        log::info!("  Code at RIP: {:02x?} ({count})", code);
    }
    
    Ok(())
}