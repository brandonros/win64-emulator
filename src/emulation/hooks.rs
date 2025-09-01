use std::cell::UnsafeCell;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::{MemType, Unicorn};

use crate::emulation::memory;
use crate::emulation::iat_hooks;
use crate::pe::constants::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};

// Thread-local state for the code hook - all in one block for efficiency
// Using UnsafeCell for maximum single-threaded performance (no RefCell overhead)
thread_local! {
    // Instruction counter
    static COUNTER: UnsafeCell<u64> = UnsafeCell::new(0);
    
    // Start time in microseconds since UNIX epoch
    static START_TIME_MICROS: UnsafeCell<u64> = UnsafeCell::new(0);
    
    // Intel formatter for disassembly output (only used when needed)
    static FORMATTER: UnsafeCell<IntelFormatter> = UnsafeCell::new({
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);
        formatter
    });
    
    // Reusable buffer for instruction bytes (32 bytes covers all x86-64 instructions)
    static CODE_BUFFER: UnsafeCell<[u8; 32]> = UnsafeCell::new([0u8; 32]);
    
    // Reusable string buffer for formatted output
    static INSTRUCTION_OUTPUT_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(64));
    
    // Reusable string buffer for log messages
    static LOG_MESSAGE_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(128));
}

pub fn get_count() -> u64 {
    COUNTER.with(|c| unsafe {
        let counter = &mut *c.get();
        *counter
    })
}

pub fn memory_read_hook_callback<D>(_emu: &mut Unicorn<D>, _mem_type: MemType, addr: u64, size: usize, _value: i64) -> bool {
    if cfg!(feature = "log-mem-read") {
        let region = memory::determine_memory_region(addr);
        log::trace!("📖 Memory read [{:?}]: 0x{:016x} (size: {} bytes)", region, addr, size);
    }
    true
}

pub fn memory_write_hook_callback<D>(_emu: &mut Unicorn<D>, _mem_type: MemType, addr: u64, size: usize, value: i64) -> bool {
    if cfg!(feature = "log-mem-write") {
        let region = memory::determine_memory_region(addr);
        log::trace!("✏️  Memory write [{:?}]: 0x{:016x} (size: {} bytes, value: 0x{:x})", region, addr, size, value);
    }
    true
}

pub fn memory_invalid_hook_callback<D>(_emu: &mut Unicorn<D>, mem_type: MemType, addr: u64, size: usize, value: i64) -> bool {
    log::info!("❌ Invalid memory access: {:?} at 0x{:016x} (size: {}, value: 0x{:x})", mem_type, addr, size, value);
    false // Don't handle the error, let it propagate
}

pub fn code_hook_callback<D>(emu: &mut Unicorn<D>, addr: u64, size: u32) {
    // Check for NULL pointer execution - this is always critical
    if addr == 0 {
        panic!("❌ Attempted to execute at NULL address (0x0000000000000000)!");
    }

    // Check if it is a missed non-intercepted winapi IAT call - this is always critical
    let mock_func_end = MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    let is_winapi_call = addr >= MOCK_FUNCTION_BASE && addr < mock_func_end;
    if is_winapi_call {
        log::logger().flush();
        panic!("reached winapi_call without iat hook/mock at 0x{:x}", addr);
    }

    // Always increment the counter (lightweight operation)
    let count = COUNTER.with(|c| unsafe {
        let counter = &mut *c.get();
        *counter += 1;
        *counter
    });

    // Early return if no features that require instruction decoding are enabled
    const NEEDS_DECODING: bool = cfg!(feature = "log-instruction") || cfg!(feature = "trace-instruction");
    if !NEEDS_DECODING {
        return;
    }

    // Only do expensive work if logging/tracing is enabled
    CODE_BUFFER.with(|buf| {
        // Safe: thread_local ensures single-threaded access
        let buffer = unsafe { &mut *buf.get() };
        
        // Read directly into the slice we need
        let slice = &mut buffer[0..size as usize];
        emu.mem_read(addr, slice).unwrap();

        // Disassemble the instruction
        let mut decoder = Decoder::with_ip(64, slice, addr, DecoderOptions::NONE);
        let instruction = decoder.decode();

        // Check if this is a REP instruction with RCX == 0 (completed)
        /*if instruction.has_rep_prefix() || instruction.has_repe_prefix() || instruction.has_repne_prefix() {
            let rcx = emu.reg_read(RegisterX86::RCX).unwrap();
            if rcx == 0 {
                // REP instruction has completed, don't count or log this
                return;
            }
        }*/

        // Format the instruction using reusable string buffer
        INSTRUCTION_OUTPUT_BUFFER.with(|instruction_output_buffer| {
            let instruction_output_buffer = unsafe { &mut *instruction_output_buffer.get() };
            instruction_output_buffer.clear(); // Clear previous content
            FORMATTER.with(|f| {
                // Safe: thread_local ensures single-threaded access
                unsafe { (*f.get()).format(&instruction, instruction_output_buffer) }
            });

            // Handle logging if enabled
            #[cfg(feature = "log-instruction")]
            {
                use std::fmt::Write;

                LOG_MESSAGE_BUFFER.with(|log_buffer| {
                    let log_msg = unsafe { &mut *log_buffer.get() };
                    log_msg.clear();
                    
                    write!(log_msg, "[{}] 0x{:016x}: {}", 
                           count, addr, instruction_output_buffer).unwrap();
                    
                    log::debug!("{}", log_msg);
                });
            }

            // Handle tracing if enabled
            #[cfg(feature = "trace-instruction")]
            {
                use crate::emulation::tracing;
                if count >= 100_000_000 {
                    tracing::trace_instruction(emu, count, instruction_output_buffer);
                }
            }

            // try to intercept iat calls?
            iat_hooks::intercept_iat_call(
                emu,
                instruction,
                size,
                addr,
                count
            );
        });
    });    
}
