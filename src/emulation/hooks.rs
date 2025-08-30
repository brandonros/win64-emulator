use std::cell::UnsafeCell;
use std::time::{SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use unicorn_engine::{MemType, RegisterX86, Unicorn};

use crate::emulation::memory::{HEAP_BASE, HEAP_SIZE, STACK_BASE, STACK_SIZE};
use crate::emulation::{iat_hooks, memory, RegisterState};
use crate::pe::constants::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE};

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
    static INSTRUCTION_OUTPUT_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(64));
    
    // Reusable string buffer for log messages
    static LOG_MESSAGE_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(128));

    // only update IPS periodically
    static LAST_IPS: UnsafeCell<f64> = UnsafeCell::new(0.0);

    // Previous register state for diffing
    static PREV_REGISTERS: UnsafeCell<RegisterState> = UnsafeCell::new(RegisterState::default());
    
    // Buffer for register diff output
    static REGISTER_DIFF_BUFFER: UnsafeCell<String> = UnsafeCell::new(String::with_capacity(256));
    
    // Flag to track if this is the first instruction
    static FIRST_INSTRUCTION: UnsafeCell<bool> = UnsafeCell::new(true);
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
    // Check for NULL pointer execution
    if addr == 0 {
        panic!("❌ Attempted to execute at NULL address (0x0000000000000000)!");
    }

    // check if stack has an issue
    let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
    
    // Check if we're executing from heap (dynamic code)
    let executing_from_heap = addr >= HEAP_BASE && addr < HEAP_BASE + HEAP_SIZE as u64;
    let rsp_in_heap = rsp >= HEAP_BASE && rsp < HEAP_BASE + HEAP_SIZE as u64;
    
    if executing_from_heap {
        log::warn!("🔥 Executing code from HEAP at 0x{:x}", addr);
        
        if rsp_in_heap {
            // This is EXPECTED for unpacked/shellcode
            log::info!("📦 Unpacked code using heap stack: RSP=0x{:x}", rsp);
            // Allow it - don't panic!
        }
    } else {
        // Only enforce stack bounds for normal code
        if rsp < STACK_BASE || rsp >= STACK_BASE + STACK_SIZE as u64 {
            // But if RSP is in heap while executing normal code, that's suspicious
            if rsp_in_heap {
                log::error!("⚠️ Regular code with heap RSP! addr=0x{:x}, RSP=0x{:x}", addr, rsp);
            }
            panic!("Stack pointer out of bounds! RSP=0x{:x}", rsp);
        }
    }
    
    // Check stack alignment (but be lenient for shellcode)
    if (rsp & 0x7) != 0 {
        if executing_from_heap {
            log::debug!("Stack misalignment in heap code (common in shellcode): RSP=0x{:x}", rsp);
            // Don't panic - shellcode often doesn't care about alignment
        } else {
            panic!("Stack misalignment detected! RSP=0x{:x}", rsp);
        }
    }

    // check if it is a missed non-intercepted winapi IAT call
    let mock_func_end = MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    let is_winapi_call = addr >= MOCK_FUNCTION_BASE && addr < mock_func_end;
    if is_winapi_call {
        panic!("reached winapi_call without iat hook/mock");
    }

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

    // Capture current register state BEFORE the instruction executes
    let current_regs = RegisterState::capture(emu);

    // Check if we have a previous state to compare against
    let is_first = FIRST_INSTRUCTION.with(|f| unsafe {
        let first = &mut *f.get();
        if *first {
            *first = false;
            true
        } else {
            false
        }
    });

    // diff registers
    if !is_first {
        // Compare with previous state and log changes
        REGISTER_DIFF_BUFFER.with(|buf| {
            PREV_REGISTERS.with(|prev| {
                let diff_buffer = unsafe { &mut *buf.get() };
                let prev_state = unsafe { &*prev.get() };
                
                prev_state.diff(&current_regs, diff_buffer);
                
                if !diff_buffer.is_empty() {
                    #[cfg(feature = "log-register-changes")]
                    log::trace!("📝 Register changes: {}", diff_buffer);
                }
            });
        });
    }

    // Store current state as previous for next instruction
    PREV_REGISTERS.with(|prev| unsafe {
        *prev.get() = current_regs;
    });

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

        // Check if this is a REP instruction with RCX == 0 (completed)
        if instruction.has_rep_prefix() || instruction.has_repe_prefix() || instruction.has_repne_prefix() {
            let rcx = emu.reg_read(RegisterX86::RCX).unwrap();
            if rcx == 0 {
                // REP instruction has completed, don't count or log this
                return;
            }
        }

        // get count
        let count = COUNTER.with(|c| unsafe {
            let counter = &mut *c.get();
            *counter += 1;
            *counter
        });

        // Only calculate IPS every N instructions instead of every instruction
        let ips = 0.0; // TODO
        
        // Format the instruction using reusable string buffer and log directly
        INSTRUCTION_OUTPUT_BUFFER.with(|instruction_output_buffer| {
            let instruction_output_buffer = unsafe { &mut *instruction_output_buffer.get() };
            instruction_output_buffer.clear(); // Clear previous content
            FORMATTER.with(|f| {
                // Safe: thread_local ensures single-threaded access
                unsafe { (*f.get()).format(&instruction, instruction_output_buffer) }
            });

            // Build log message string
            use iced_x86::{Mnemonic, OpKind};
            let mnemonic = instruction.mnemonic();
            
            // Build the base log message using the reusable buffer
            LOG_MESSAGE_BUFFER.with(|log_buffer| {
                let log_msg = unsafe { &mut *log_buffer.get() };
                log_msg.clear();
                use std::fmt::Write;
                
                // Check if instruction uses segment registers (GS/FS for TEB/PEB access)
                let segment_info = {
                    // Check for explicit segment prefix
                    if instruction.segment_prefix() == iced_x86::Register::GS {
                        " [GS:TEB]"
                    } else if instruction.segment_prefix() == iced_x86::Register::FS {
                        " [FS]"
                    } else {
                        // Check if any memory operand uses GS or FS
                        let mut seg_info = "";
                        for i in 0..instruction.op_count() {
                            if instruction.op_kind(i) == iced_x86::OpKind::Memory {
                                let seg = instruction.memory_segment();
                                if seg == iced_x86::Register::GS {
                                    seg_info = " [GS:TEB via memory operand]";
                                    break;
                                } else if seg == iced_x86::Register::FS {
                                    seg_info = " [FS via memory operand]";
                                    break;
                                }
                            }
                        }
                        seg_info
                    }
                };
                
                write!(log_msg, "  {:.0} ops/sec | [{}] 0x{:016x}: {}{}", 
                       ips, count, addr, instruction_output_buffer, segment_info).unwrap();
                
                // For indirect jumps/calls, try to show the target address
                let mut is_jump_or_call = false;
                if (mnemonic == Mnemonic::Jmp || mnemonic == Mnemonic::Call) && 
                   instruction.op_count() > 0 && 
                   instruction.op0_kind() == OpKind::Memory {
                    
                    // Get the memory address being dereferenced
                    let mem_addr = instruction.memory_displacement64();
                    
                    // Try to read the target address from memory
                    let mut target_bytes = [0u8; 8];
                    if emu.mem_read(mem_addr, &mut target_bytes).is_ok() {
                        let target = u64::from_le_bytes(target_bytes);
                        
                        // Check if we're about to jump to NULL
                        if target == 0 {
                            log::error!("❌ Attempted jump to NULL address from 0x{:016x}!", addr);
                            log::debug!("{} -> 0x{:016x}", log_msg, target);
                            log::logger().flush();
                            panic!("out");
                        }
                        
                        // Append target address to log message
                        write!(log_msg, " -> 0x{:016x}", target).unwrap();
                    }

                    is_jump_or_call = true;
                }

                if is_jump_or_call || count >= 231106700 {
                    log::debug!("{}", log_msg);
                } else {
                    #[cfg(feature = "log-instruction")]
                    log::debug!("{}", log_msg);
                }

                // trace
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
    });    
}
