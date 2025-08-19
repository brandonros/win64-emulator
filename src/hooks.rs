use std::cell::UnsafeCell;
use std::time::{SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::Unicorn;

use crate::pe64_emulator::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};

// Thread-local state for the code hook - all in one block for efficiency
// Using UnsafeCell for maximum single-threaded performance (no RefCell overhead)
thread_local! {
    // Instruction counter
    static COUNTER: UnsafeCell<u64> = UnsafeCell::new(0);
    
    // Start time in microseconds since UNIX epoch
    static START_TIME_MICROS: UnsafeCell<u64> = UnsafeCell::new(0);
    
    // Intel formatter for disassembly output
    static FORMATTER: UnsafeCell<IntelFormatter> = UnsafeCell::new({
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);
        formatter
    });
    
    // Reusable buffer for instruction bytes (32 bytes covers all x86-64 instructions)
    static CODE_BUFFER: UnsafeCell<[u8; 32]> = UnsafeCell::new([0u8; 32]);
    
    // Reusable string buffer for formatted output
    static OUTPUT_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(64));

    // only update IPS periodically
    static LAST_IPS: UnsafeCell<f64> = UnsafeCell::new(0.0);
}

pub fn code_hook_callback<D>(emu: &mut Unicorn<D>, addr: u64, size: u32) {
    // Safe: single-threaded execution only
    let count = COUNTER.with(|c| unsafe {
        let counter = &mut *c.get();
        *counter += 1;
        *counter
    });
    
    // Initialize start time on first call
    let _start_micros = START_TIME_MICROS.with(|s| unsafe {
        let start_ptr = &mut *s.get();
        if *start_ptr == 0 {
            *start_ptr = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
        }
        *start_ptr
    });

    // Only calculate IPS every 10000 instructions instead of every instruction
    let ips = if count % 10000 == 0 {
        // Calculate and cache new IPS
        let start_micros = START_TIME_MICROS.with(|s| unsafe { *s.get() });
        let now_micros = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
        let elapsed_micros = now_micros.saturating_sub(start_micros).max(1);
        let new_ips = (count as f64) / (elapsed_micros as f64 / 1_000_000.0);
        LAST_IPS.with(|i| unsafe { *i.get() = new_ips });
        new_ips
    } else {
        // Use cached IPS
        LAST_IPS.with(|i| unsafe { *i.get() })
    };
    
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
    
    // Read and decode and log the instruction
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
            
            // Log directly using the buffer - no clone needed!
            log::info!("  {:.0} ops/sec | [{}] 0x{:016x}: {}", 
                    ips, count, addr, output);
        });
    });
}
