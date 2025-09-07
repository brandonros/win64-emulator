use crate::{emulation::code_hooks, pe::{LoadedPE, constants}};
use super::memory::STACK_BASE;
use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn setup_cpu_state(emu: &mut dyn EmulatorEngine, pe: &LoadedPE) -> Result<(), EmulatorError> {
    log::info!("\n🖥️  Setting up CPU state:");
    
    // Set entry point
    emu.reg_write(X86Register::RIP, pe.entry_point())?;
    log::info!("  RIP: 0x{:016x}", pe.entry_point());
    
    // Set stack pointer
    let stack_pointer = STACK_BASE + 0x100000 as u64;
    emu.reg_write(X86Register::RSP, stack_pointer)?;
    log::info!("  RSP: 0x{:016x}", stack_pointer);
    
    // Set up basic registers (Windows x64 ABI)
    emu.reg_write(X86Register::RBP, STACK_BASE + 0x100000 as u64 + 0x1000)?;
    
    // Clear other registers
    for &reg in &[X86Register::RAX, X86Register::RBX, X86Register::RCX, 
                  X86Register::RDX, X86Register::RSI, X86Register::RDI] {
        emu.reg_write(reg, 0)?;
    }
    
    Ok(())
}

pub fn setup_dll_cpu_state(emu: &mut dyn EmulatorEngine, pe: &LoadedPE, reason: u32) -> Result<(), EmulatorError> {
    log::info!("\n🖥️  Setting up CPU state for DLL:");
    
    // Set entry point (DllMain)
    emu.reg_write(X86Register::RIP, pe.entry_point())?;
    log::info!("  RIP: 0x{:016x} (DllMain)", pe.entry_point());
    
    // Set stack pointer
    let stack_pointer = STACK_BASE + 0x100000 as u64;
    emu.reg_write(X86Register::RSP, stack_pointer)?;
    log::info!("  RSP: 0x{:016x}", stack_pointer);
    
    // Set up DllMain parameters (Windows x64 ABI)
    // BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    // RCX = hinstDLL (module base)
    // RDX = fdwReason (DLL_PROCESS_ATTACH, etc.)
    // R8 = lpReserved (NULL for dynamic load)
    emu.reg_write(X86Register::RCX, pe.image_base())?;  // hinstDLL
    emu.reg_write(X86Register::RDX, reason as u64)?;     // fdwReason
    emu.reg_write(X86Register::R8, 0)?;                  // lpReserved (NULL)
    
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
    emu.reg_write(X86Register::RSP, stack_pointer - 8)?;
    
    // Set up basic registers
    emu.reg_write(X86Register::RBP, STACK_BASE + 0x100000 as u64 + 0x1000)?;
    
    // Clear other registers
    for &reg in &[X86Register::RAX, X86Register::RBX, 
                  X86Register::RSI, X86Register::RDI, X86Register::R9] {
        emu.reg_write(reg, 0)?;
    }
    
    Ok(())
}

pub fn dump_cpu_state(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    log::info!("\n📊 CPU State:");
    
    let registers = [
        ("RIP", X86Register::RIP),
        ("RSP", X86Register::RSP),
        ("RBP", X86Register::RBP),
        ("RAX", X86Register::RAX),
        ("RBX", X86Register::RBX),
        ("RCX", X86Register::RCX),
        ("RDX", X86Register::RDX),
        ("RSI", X86Register::RSI),
        ("RDI", X86Register::RDI),
        ("R8",  X86Register::R8),
        ("R9",  X86Register::R9),
        ("R10", X86Register::R10),
        ("R11", X86Register::R11),
        ("R12", X86Register::R12),
        ("R13", X86Register::R13),
        ("R14", X86Register::R14),
        ("R15", X86Register::R15),
    ];
    
    // log registers
    for (name, reg) in registers {
        let value = emu.reg_read(reg)?;
        log::info!("  {}: 0x{:016x}", name, value);
    }

    // RFLAGS (super useful for debugging conditionals and exceptions)
    let rflags = emu.reg_read(X86Register::RFLAGS)?;
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
    let fs = emu.reg_read(X86Register::FS)?;
    let gs = emu.reg_read(X86Register::GS)?;
    if fs != 0 || gs != 0 {
        log::info!("  FS: 0x{:016x}  GS: 0x{:016x}", fs, gs);
    }
    
    // Stack preview (top few values)
    let rsp = emu.reg_read(X86Register::RSP)?;
    log::info!("  Stack preview:");
    for i in 0..4 {
        let mut bytes = vec![0u8; 8];
        if emu.mem_read(rsp + i*8, &mut bytes).is_ok() {
            let value = u64::from_le_bytes(bytes.try_into().unwrap());
            log::info!("    [RSP+0x{:02x}]: 0x{:016x}", i*8, value);
        }
    }
    
    // Show some memory around RIP
    let count = code_hooks::get_count();
    let rip = emu.reg_read(X86Register::RIP)?;
    let mut code = vec![0u8; 16];
    if emu.mem_read(rip, &mut code).is_ok() {
        log::info!("  Code at RIP: {:02x?} ({count})", code);
    }
    
    Ok(())
}