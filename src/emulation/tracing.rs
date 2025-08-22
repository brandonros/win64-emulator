// tracing.rs

use std::cell::UnsafeCell;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use unicorn_engine::{RegisterX86, Unicorn};

// This covers all general purpose registers + RIP + instruction counter
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct TraceRecord {
    pub instruction_count: u64,  // 8 bytes
    pub rip: u64,                // 8 bytes
    pub rflags: u64,              // 8 bytes
    pub rax: u64,                 // 8 bytes
    pub rbx: u64,                 // 8 bytes
    pub rcx: u64,                 // 8 bytes
    pub rdx: u64,                 // 8 bytes
    pub rsi: u64,                 // 8 bytes
    pub rdi: u64,                 // 8 bytes
    pub rbp: u64,                 // 8 bytes
    pub rsp: u64,                 // 8 bytes
    pub r8: u64,                  // 8 bytes
    pub r9: u64,                  // 8 bytes
    pub r10: u64,                 // 8 bytes
    pub r11: u64,                 // 8 bytes
    pub r12: u64,                 // 8 bytes
    pub r13: u64,                 // 8 bytes
    pub r14: u64,                 // 8 bytes
    pub r15: u64,                 // 8 bytes
    pub disassembly: [u8; 64]
}

impl TraceRecord {
    pub fn capture<D>(emu: &Unicorn<D>, instruction_count: u64, disassembly: &str) -> Self {
        // copy disassembly to bytes
        let mut temp = [0; 64];
        let bytes = disassembly.as_bytes();
        let copy_len = std::cmp::min(bytes.len(), 63);
        temp[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Self {
            instruction_count,
            rip: emu.reg_read(RegisterX86::RIP).unwrap_or(0),
            rflags: emu.reg_read(RegisterX86::RFLAGS).unwrap_or(0),
            rax: emu.reg_read(RegisterX86::RAX).unwrap_or(0),
            rbx: emu.reg_read(RegisterX86::RBX).unwrap_or(0),
            rcx: emu.reg_read(RegisterX86::RCX).unwrap_or(0),
            rdx: emu.reg_read(RegisterX86::RDX).unwrap_or(0),
            rsi: emu.reg_read(RegisterX86::RSI).unwrap_or(0),
            rdi: emu.reg_read(RegisterX86::RDI).unwrap_or(0),
            rbp: emu.reg_read(RegisterX86::RBP).unwrap_or(0),
            rsp: emu.reg_read(RegisterX86::RSP).unwrap_or(0),
            r8: emu.reg_read(RegisterX86::R8).unwrap_or(0),
            r9: emu.reg_read(RegisterX86::R9).unwrap_or(0),
            r10: emu.reg_read(RegisterX86::R10).unwrap_or(0),
            r11: emu.reg_read(RegisterX86::R11).unwrap_or(0),
            r12: emu.reg_read(RegisterX86::R12).unwrap_or(0),
            r13: emu.reg_read(RegisterX86::R13).unwrap_or(0),
            r14: emu.reg_read(RegisterX86::R14).unwrap_or(0),
            r15: emu.reg_read(RegisterX86::R15).unwrap_or(0),
            disassembly: temp
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>()
            )
        }
    }
}

// Thread-local trace writer
thread_local! {
    // The actual writer - None if tracing is disabled
    static TRACE_WRITER: UnsafeCell<Option<BufWriter<File>>> = UnsafeCell::new(None);
    
    // Counter for periodic flushing
    static TRACE_RECORDS_WRITTEN: UnsafeCell<u64> = UnsafeCell::new(0);
    
    // Reusable buffer for the trace record to avoid allocations
    static TRACE_RECORD_BUFFER: UnsafeCell<TraceRecord> = UnsafeCell::new(unsafe { std::mem::zeroed() });
}

pub fn init_tracing(path: impl AsRef<Path>) -> std::io::Result<()> {
    let file = File::create(path)?;
    // 16MB buffer for maximum efficiency
    let writer = BufWriter::with_capacity(16 * 1024 * 1024, file);
    
    TRACE_WRITER.with(|w| unsafe {
        *w.get() = Some(writer);
    });
    
    log::info!("📝 Trace logging initialized");
    Ok(())
}

#[inline(always)]
pub fn trace_instruction<D>(emu: &Unicorn<D>, instruction_count: u64, disassembly: &str) {
    TRACE_WRITER.with(|writer_cell| {
        let writer = unsafe { &mut *writer_cell.get() };
        if let Some(w) = writer {
            // Capture directly into our reusable buffer
            TRACE_RECORD_BUFFER.with(|rec_cell| {
                let record = unsafe { &mut *rec_cell.get() };
                *record = TraceRecord::capture(emu, instruction_count, disassembly);
                
                // Write the record
                if let Err(e) = w.write_all(record.as_bytes()) {
                    log::error!("Failed to write trace record: {}", e);
                    return;
                }
            });
            
            // Update counter and flush periodically
            TRACE_RECORDS_WRITTEN.with(|count_cell| {
                let count = unsafe { &mut *count_cell.get() };
                *count += 1;
                
                // Flush every 1M records to avoid losing too much data if we crash
                if *count % 1_000_000 == 0 {
                    if let Err(e) = w.flush() {
                        log::error!("Failed to flush trace: {}", e);
                    } else {
                        log::debug!("Trace: Flushed {} records", count);
                    }
                }
            });
        }
    });
}

pub fn flush_trace() {
    TRACE_WRITER.with(|writer_cell| {
        let writer = unsafe { &mut *writer_cell.get() };
        if let Some(w) = writer {
            if let Err(e) = w.flush() {
                log::error!("Failed to flush trace: {}", e);
            } else {
                TRACE_RECORDS_WRITTEN.with(|count_cell| {
                    let count = unsafe { *count_cell.get() };
                    log::info!("📝 Flushed {} trace records", count);
                });
            }
        }
    });
}
