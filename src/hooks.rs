use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::Unicorn;

use crate::pe64_emulator::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};

static COUNTER: AtomicU64 = AtomicU64::new(0);

static START_TIME: LazyLock<Instant> = LazyLock::new(|| Instant::now());

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

pub fn code_hook_callback<D>(emu: &mut Unicorn<D>, addr: u64, size: u32) {
    let count = COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    
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
    
    // Read the instruction bytes
    let mut code_bytes = vec![0u8; size as usize];
    emu.mem_read(addr, &mut code_bytes).unwrap();
    
    // Disassemble the instruction
    let mut decoder = Decoder::with_ip(64, &code_bytes, addr, DecoderOptions::NONE);
    let instruction = decoder.decode();
    
    // Format the instruction
    let mut output = String::new();
    FORMATTER.with(|f| {
        // Safe: thread_local ensures single-threaded access
        unsafe { (*f.get()).format(&instruction, &mut output) }
    });
    
    // Calculate instructions per second
    let elapsed = START_TIME.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.000001); // Avoid divide by zero
    let ips = count as f64 / elapsed_secs;
    log::info!("  {:.0} ops/sec | [{}] 0x{:016x}: {}", 
            ips, count, addr, output);
}
