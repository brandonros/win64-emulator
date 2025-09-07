use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::time::Instant;
use crate::emulation::memory;

pub fn QueryPerformanceCounter(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get the pointer to i64 from RCX register
    let performance_count_ptr = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[QueryPerformanceCounter] performance_count_ptr: 0x{:x}", performance_count_ptr);
    
    if performance_count_ptr > 0 {
        // Get a high-resolution timestamp
        // Using Instant::now() which provides high-resolution timing
        let now = Instant::now();
        
        // Convert to a 64-bit counter value
        // We'll use nanoseconds since it's high resolution
        // In real Windows, this would be based on the system's performance frequency
        // For emulation purposes, we'll simulate a reasonable high-resolution counter
        let elapsed_nanos = now.elapsed().as_nanos() as u64;
        
        // Create a mock performance counter value
        // We'll use a base offset plus elapsed time to simulate a running counter
        const BASE_COUNTER: u64 = 1000000000; // Arbitrary base value
        let counter_value = BASE_COUNTER + elapsed_nanos;
        
        // Write the i64 counter value directly to memory
        memory::write_qword_le(emu, performance_count_ptr, counter_value);
        
        // Set return value to TRUE (non-zero) in RAX register
        emu.reg_write(X86Register::RAX, 1)?;
    } else {
        // Set return value to FALSE (zero) in RAX register
        emu.reg_write(X86Register::RAX, 0)?;
    }
    
    Ok(())
}