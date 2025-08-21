use std::fmt::Write;
use unicorn_engine::{RegisterX86, Unicorn};

// Struct to hold all x86-64 general purpose and common registers
#[derive(Clone, Copy, Default)]
pub struct RegisterState {
    // General purpose registers
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64,  r9: u64,  r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

impl RegisterState {
    pub fn capture<D>(emu: &Unicorn<D>) -> Self {
        Self {
            rax: emu.reg_read(RegisterX86::RAX).unwrap_or(0),
            rbx: emu.reg_read(RegisterX86::RBX).unwrap_or(0),
            rcx: emu.reg_read(RegisterX86::RCX).unwrap_or(0),
            rdx: emu.reg_read(RegisterX86::RDX).unwrap_or(0),
            rsi: emu.reg_read(RegisterX86::RSI).unwrap_or(0),
            rdi: emu.reg_read(RegisterX86::RDI).unwrap_or(0),
            rbp: emu.reg_read(RegisterX86::RBP).unwrap_or(0),
            rsp: emu.reg_read(RegisterX86::RSP).unwrap_or(0),
            r8:  emu.reg_read(RegisterX86::R8).unwrap_or(0),
            r9:  emu.reg_read(RegisterX86::R9).unwrap_or(0),
            r10: emu.reg_read(RegisterX86::R10).unwrap_or(0),
            r11: emu.reg_read(RegisterX86::R11).unwrap_or(0),
            r12: emu.reg_read(RegisterX86::R12).unwrap_or(0),
            r13: emu.reg_read(RegisterX86::R13).unwrap_or(0),
            r14: emu.reg_read(RegisterX86::R14).unwrap_or(0),
            r15: emu.reg_read(RegisterX86::R15).unwrap_or(0),
        }
    }
    
    pub fn diff(&self, new: &RegisterState, output: &mut String) {
        output.clear();
        
        // Check each register and append changes
        macro_rules! check_reg {
            ($name:ident, $display:expr) => {
                if self.$name != new.$name {
                    if !output.is_empty() { output.push_str(", "); }
                    write!(output, "{}: 0x{:016x} → 0x{:016x}", 
                           $display, self.$name, new.$name).unwrap();
                }
            };
        }
        
        check_reg!(rax, "RAX");
        check_reg!(rbx, "RBX");
        check_reg!(rcx, "RCX");
        check_reg!(rdx, "RDX");
        check_reg!(rsi, "RSI");
        check_reg!(rdi, "RDI");
        check_reg!(rbp, "RBP");
        check_reg!(rsp, "RSP");
        check_reg!(r8,  "R8");
        check_reg!(r9,  "R9");
        check_reg!(r10, "R10");
        check_reg!(r11, "R11");
        check_reg!(r12, "R12");
        check_reg!(r13, "R13");
        check_reg!(r14, "R14");
        check_reg!(r15, "R15");
    }
}