use std::cell::UnsafeCell;
use std::time::{SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::Unicorn;

use crate::pe64_emulator::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};

// Thread-local counters for maximum single-threaded performance
// No atomic overhead, direct memory access
thread_local! {
    static COUNTER: UnsafeCell<u64> = UnsafeCell::new(0);
    static START_TIME_MICROS: UnsafeCell<u64> = UnsafeCell::new(0);
}

// Thread-local formatter with minimal overhead
// Safe because it's only accessed from single thread
thread_local! {
    static FORMATTER: UnsafeCell<IntelFormatter> = UnsafeCell::new({
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);
        formatter
    });
}

// Thread-local reusable buffer for instruction bytes
// Avoids heap allocation on every instruction
// Safe: single-threaded access only (thread_local)
// 32 bytes is enough for any x86-64 instruction (max is 15 bytes)
thread_local! {
    static CODE_BUFFER: UnsafeCell<[u8; 32]> = UnsafeCell::new([0u8; 32]);
}

// Thread-local reusable string buffer for formatted output
// Avoids heap allocation on every instruction
thread_local! {
    static OUTPUT_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(64));
}

pub fn code_hook_callback<D>(emu: &mut Unicorn<D>, addr: u64, size: u32) {
    // Safe: single-threaded execution only
    let count = COUNTER.with(|c| unsafe {
        let counter = &mut *c.get();
        *counter += 1;
        *counter
    });
    
    // Initialize start time on first call
    let start_micros = START_TIME_MICROS.with(|s| unsafe {
        let start_ptr = &mut *s.get();
        if *start_ptr == 0 {
            *start_ptr = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
        }
        *start_ptr
    });
    
    // Check if we're about to execute in the mock IAT function range
    let mock_func_end = MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    if addr >= MOCK_FUNCTION_BASE && addr < mock_func_end {
        // Look up which function this is
        let function_info = crate::pe64_emulator::IAT_FUNCTION_MAP
            .read()
            .unwrap()
            .get(&addr)
            .map(|info| format!("{}!{}", info.0, info.1))
            .unwrap_or_else(|| "Unknown IAT function".to_string());
        
        log::info!("🛑 STOPPING: About to execute IAT function at 0x{:016x}", addr);
        log::info!("   Function: {}", function_info);
        log::info!("   This is a mock IAT function - execution should not reach here!");
        panic!("IAT function {} reached at 0x{:016x}", function_info, addr);
    }
    
    // Read and decode the instruction
    CODE_BUFFER.with(|buf| {
        // Safe: thread_local ensures single-threaded access
        let buffer = unsafe { &mut *buf.get() };
        
        // Read directly into the slice we need
        let slice = &mut buffer[0..size as usize];
        emu.mem_read(addr, slice).unwrap();
        
        // Disassemble the instruction
        let mut decoder = Decoder::with_ip(64, slice, addr, DecoderOptions::NONE);
        let instruction = decoder.decode();
        
        // Format the instruction using reusable string buffer and log directly
        OUTPUT_BUFFER.with(|out| {
            let output = unsafe { &mut *out.get() };
            output.clear(); // Clear previous content
            FORMATTER.with(|f| {
                // Safe: thread_local ensures single-threaded access
                unsafe { (*f.get()).format(&instruction, output) }
            });
            
            // Calculate instructions per second
            let now_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            let elapsed_micros = now_micros.saturating_sub(start_micros).max(1); // Avoid divide by zero
            let elapsed_secs = elapsed_micros as f64 / 1_000_000.0;
            let ips = count as f64 / elapsed_secs;
            
            // Log directly using the buffer - no clone needed!
            log::info!("  {:.0} ops/sec | [{}] 0x{:016x}: {}", 
                    ips, count, addr, output);
        });
    });
}
