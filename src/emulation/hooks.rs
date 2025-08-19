use std::cell::UnsafeCell;
use std::time::{SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::Unicorn;

use crate::pe::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};
use super::iat::IAT_FUNCTION_MAP;
use crate::winapi;

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

    // Only calculate IPS every 1000 instructions instead of every instruction
    let _ips = if count % 1000 == 0 {
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
            
            // Log directly using the buffer
            //log::info!("  {:.0} ops/sec | [{}] 0x{:016x}: {}", ips, count, addr, output);
        });
    });

    // Check if we're about to execute in the mock IAT function range
    let mock_func_end = MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    if addr >= MOCK_FUNCTION_BASE && addr < mock_func_end {
        // Look up which function this is - panic if not found
        let function_info = IAT_FUNCTION_MAP
            .read()
            .unwrap()
            .get(&addr)
            .map(|info| (info.0.clone(), info.1.clone()))
            .expect(&format!("Mock function at 0x{:016x} not found in IAT_FUNCTION_MAP! This is a bug.", addr));
        
        // Handle the API call using the centralized dispatcher
        log::info!("🔷 API Call: {}!{}", function_info.0, function_info.1);
        winapi::handle_winapi_call(emu, &function_info.0, &function_info.1);
        
        // Skip the mock function by advancing RIP to the return address
        // Pop return address from stack and jump to it
        let rsp = emu.reg_read(unicorn_engine::RegisterX86::RSP).unwrap();
        let mut return_addr = [0u8; 8];
        emu.mem_read(rsp, &mut return_addr).unwrap();
        let return_addr = u64::from_le_bytes(return_addr);
        
        // Update RSP (pop the return address)
        emu.reg_write(unicorn_engine::RegisterX86::RSP, rsp + 8).unwrap();
        
        // Jump to return address
        emu.reg_write(unicorn_engine::RegisterX86::RIP, return_addr).unwrap();
    }
}
