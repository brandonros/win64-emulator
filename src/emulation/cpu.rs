use unicorn_engine::{uc_error, RegisterX86, Unicorn};
use crate::pe::LoadedPE;
use super::memory::{STACK_BASE, STACK_SIZE, TEB_BASE};

pub fn setup_cpu_state(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
    log::info!("\n🖥️  Setting up CPU state:");
    
    // Set entry point
    emu.reg_write(RegisterX86::RIP, pe.entry_point())?;
    log::info!("  RIP: 0x{:016x}", pe.entry_point());
    
    // Set stack pointer
    let stack_pointer = STACK_BASE + (STACK_SIZE as u64 / 2); // Middle of stack
    emu.reg_write(RegisterX86::RSP, stack_pointer)?;
    log::info!("  RSP: 0x{:016x}", stack_pointer);
    
    // Set up basic registers (Windows x64 ABI)
    emu.reg_write(RegisterX86::RBP, stack_pointer)?;
    
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
    let rip = emu.reg_read(RegisterX86::RIP)?;
    let mut code = vec![0u8; 16];
    if emu.mem_read(rip, &mut code).is_ok() {
        log::info!("  Code at RIP: {:02x?}", code);
    }
    
    Ok(())
}