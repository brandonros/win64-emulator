use unicorn_engine::{Unicorn, RegisterX86};

pub fn RtlCaptureContext(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // void RtlCaptureContext(
    //   PCONTEXT ContextRecord  // RCX
    // )
    
    let context_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[RtlCaptureContext] ContextRecord: 0x{:x}", context_ptr);
    
    // Check for NULL pointer
    if context_ptr == 0 {
        log::warn!("[RtlCaptureContext] NULL context pointer provided");
        return Ok(());
    }
    
    // The CONTEXT structure on x64 is quite large (~1232 bytes)
    // We'll fill in the most important fields for a mock implementation
    
    // CONTEXT structure offsets for x64
    const CONTEXT_P1HOME: usize = 0x00;
    const CONTEXT_P2HOME: usize = 0x08;
    const CONTEXT_P3HOME: usize = 0x10;
    const CONTEXT_P4HOME: usize = 0x18;
    const CONTEXT_P5HOME: usize = 0x20;
    const CONTEXT_P6HOME: usize = 0x28;
    const CONTEXT_FLAGS: usize = 0x30;
    const CONTEXT_MXCSR: usize = 0x34;
    const CONTEXT_SEGCS: usize = 0x38;
    const CONTEXT_SEGDS: usize = 0x3A;
    const CONTEXT_SEGES: usize = 0x3C;
    const CONTEXT_SEGFS: usize = 0x3E;
    const CONTEXT_SEGGS: usize = 0x40;
    const CONTEXT_SEGSS: usize = 0x42;
    const CONTEXT_EFLAGS: usize = 0x44;
    const CONTEXT_DR0: usize = 0x48;
    const CONTEXT_RAX: usize = 0x78;
    const CONTEXT_RCX: usize = 0x80;
    const CONTEXT_RDX: usize = 0x88;
    const CONTEXT_RBX: usize = 0x90;
    const CONTEXT_RSP: usize = 0x98;
    const CONTEXT_RBP: usize = 0xA0;
    const CONTEXT_RSI: usize = 0xA8;
    const CONTEXT_RDI: usize = 0xB0;
    const CONTEXT_R8: usize = 0xB8;
    const CONTEXT_R9: usize = 0xC0;
    const CONTEXT_R10: usize = 0xC8;
    const CONTEXT_R11: usize = 0xD0;
    const CONTEXT_R12: usize = 0xD8;
    const CONTEXT_R13: usize = 0xE0;
    const CONTEXT_R14: usize = 0xE8;
    const CONTEXT_R15: usize = 0xF0;
    const CONTEXT_RIP: usize = 0xF8;
    
    // Context flags
    const CONTEXT_AMD64: u32 = 0x00100000;
    const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x00000001;
    const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x00000002;
    const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x00000004;
    const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    
    // Set context flags
    let flags = CONTEXT_FULL;
    emu.mem_write(context_ptr + CONTEXT_FLAGS as u64, &flags.to_le_bytes())?;
    
    // Capture general purpose registers
    let rax = emu.reg_read(RegisterX86::RAX)?;
    let rcx = emu.reg_read(RegisterX86::RCX)?;
    let rdx = emu.reg_read(RegisterX86::RDX)?;
    let rbx = emu.reg_read(RegisterX86::RBX)?;
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let rbp = emu.reg_read(RegisterX86::RBP)?;
    let rsi = emu.reg_read(RegisterX86::RSI)?;
    let rdi = emu.reg_read(RegisterX86::RDI)?;
    let r8 = emu.reg_read(RegisterX86::R8)?;
    let r9 = emu.reg_read(RegisterX86::R9)?;
    let r10 = emu.reg_read(RegisterX86::R10)?;
    let r11 = emu.reg_read(RegisterX86::R11)?;
    let r12 = emu.reg_read(RegisterX86::R12)?;
    let r13 = emu.reg_read(RegisterX86::R13)?;
    let r14 = emu.reg_read(RegisterX86::R14)?;
    let r15 = emu.reg_read(RegisterX86::R15)?;
    let rip = emu.reg_read(RegisterX86::RIP)?;
    let rflags = emu.reg_read(RegisterX86::RFLAGS)?;
    
    // Write registers to CONTEXT structure
    emu.mem_write(context_ptr + CONTEXT_RAX as u64, &rax.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RCX as u64, &rcx.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RDX as u64, &rdx.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RBX as u64, &rbx.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RSP as u64, &rsp.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RBP as u64, &rbp.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RSI as u64, &rsi.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RDI as u64, &rdi.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R8 as u64, &r8.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R9 as u64, &r9.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R10 as u64, &r10.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R11 as u64, &r11.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R12 as u64, &r12.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R13 as u64, &r13.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R14 as u64, &r14.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_R15 as u64, &r15.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_RIP as u64, &rip.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_EFLAGS as u64, &(rflags as u32).to_le_bytes())?;
    
    // Write segment registers (mock values)
    let cs: u16 = 0x33;  // Typical x64 CS value
    let ds: u16 = 0x2B;  // Typical x64 DS value
    let es: u16 = 0x2B;
    let fs: u16 = 0x53;
    let gs: u16 = 0x2B;
    let ss: u16 = 0x2B;
    
    emu.mem_write(context_ptr + CONTEXT_SEGCS as u64, &cs.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_SEGDS as u64, &ds.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_SEGES as u64, &es.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_SEGFS as u64, &fs.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_SEGGS as u64, &gs.to_le_bytes())?;
    emu.mem_write(context_ptr + CONTEXT_SEGSS as u64, &ss.to_le_bytes())?;
    
    log::info!("[RtlCaptureContext] Captured context: RIP=0x{:x}, RSP=0x{:x}", rip, rsp);
    log::warn!("[RtlCaptureContext] Mock implementation - some fields not filled");
    
    // RtlCaptureContext returns void
    
    Ok(())
}