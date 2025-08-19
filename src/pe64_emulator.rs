use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, Formatter as _, IntelFormatter};
use unicorn_engine::{uc_error, Arch, Mode, Permission, RegisterX86, Unicorn};

use crate::{loaded_pe::LoadedPE, loader_error::LoaderError, structs::ImportedFunction};

pub struct PE64Emulator {
    emu: Unicorn<'static, ()>,
    loaded_pe: LoadedPE,
}

impl PE64Emulator {
    pub fn new(pe_path: &str) -> Result<Self, LoaderError> {
        let loaded_pe = LoadedPE::from_file(pe_path)?;
        let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)?;
        
        // Set up memory regions for the PE
        Self::setup_memory(&mut emu, &loaded_pe)?;
        
        // Populate IAT with mock function addresses
        Self::setup_iat(&mut emu, &loaded_pe)?;
        
        // Set up initial CPU state
        Self::setup_cpu_state(&mut emu, &loaded_pe)?;
        
        Ok(PE64Emulator { emu, loaded_pe })
    }
    
    fn setup_memory(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
        log::info!("\n🗺️  Setting up memory layout:");
        
        // For packed executables, we need to ensure the entry point is covered
        let entry_point = pe.entry_point();
        
        // Calculate total memory needed, including entry point
        let mut min_addr = entry_point.min(pe.image_base());
        let mut max_addr = entry_point.max(pe.image_base());
        
        for section in pe.sections() {
            min_addr = min_addr.min(section.virtual_address());
            max_addr = max_addr.max(section.virtual_address() + section.virtual_size());
        }
        
        // Ensure entry point is covered
        min_addr = min_addr.min(entry_point);
        max_addr = max_addr.max(entry_point + 0x1000); // Give some space around entry point
        
        // Align to page boundaries
        let page_size = 0x1000;
        min_addr = min_addr & !(page_size - 1);
        max_addr = (max_addr + page_size - 1) & !(page_size - 1);
        
        let total_size = max_addr - min_addr;
        
        log::info!("  Image range: 0x{:016x} - 0x{:016x} (size: 0x{:x})", 
                 min_addr, max_addr, total_size);
        log::info!("  Entry point: 0x{:016x} (covered: {})", 
                 entry_point, entry_point >= min_addr && entry_point < max_addr);
        
        // Map the entire image range
        emu.mem_map(min_addr, total_size as usize, Permission::READ | Permission::WRITE | Permission::EXEC)?;
        
        // Load section data
        for section in pe.sections() {
            if !section.raw_data().is_empty() {
                emu.mem_write(section.virtual_address(), &section.raw_data())?;
                log::info!("  Loaded section '{}' at 0x{:016x}", 
                         section.name(), section.virtual_address());
            }
        }
        
        // Check if entry point has code - if not, this might be a packed executable
        let mut entry_code = vec![0u8; 16];
        if let Ok(()) = emu.mem_read(entry_point, &mut entry_code) {
            let has_code = entry_code.iter().any(|&b| b != 0);
            log::info!("  Entry point has code: {} (first bytes: {:02x?})", 
                     has_code, &entry_code[..8]);
            
            if !has_code {
                log::info!("  ⚠️  Entry point appears to be unmapped - this may be a packed executable");
                log::info!("      Consider using a different unpacking approach or manual analysis");
            }
        }
        
        // Set up stack
        let stack_base = 0x7fff0000;
        let stack_size = 0x10000;
        if stack_base >= max_addr || stack_base + stack_size as u64 <= min_addr {
            emu.mem_map(stack_base, stack_size, Permission::READ | Permission::WRITE)?;
            log::info!("  Stack: 0x{:016x} - 0x{:016x}", stack_base, stack_base + stack_size as u64);
        }
        
        // Set up heap (basic)
        let heap_base = 0x10000000;
        let heap_size = 0x100000;
        if heap_base >= max_addr || heap_base + heap_size as u64 <= min_addr {
            emu.mem_map(heap_base, heap_size, Permission::READ | Permission::WRITE)?;
            log::info!("  Heap: 0x{:016x} - 0x{:016x}", heap_base, heap_base + heap_size as u64);
        }
        
        Ok(())
    }
    
    fn setup_iat(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
        log::info!("\n📌 Setting up Import Address Table:");
        
        // Map memory for mock functions if we have any IAT entries
        if !pe.iat_entries().is_empty() {
            let mock_function_base = 0x7F000000u64;
            let mock_size = 0x10000;
            emu.mem_map(mock_function_base, mock_size, Permission::READ | Permission::EXEC)?;
            
            // Write resolved addresses to IAT
            for entry in pe.iat_entries() {
                // Write the resolved address to the IAT entry
                let resolved_addr_bytes = entry.resolved_address.to_le_bytes();
                emu.mem_write(entry.iat_address, &resolved_addr_bytes)?;
                
                // No need to write anything at the mock address - we'll panic if we get there
                
                log::info!("  IAT[0x{:016x}] = 0x{:016x} ({}!{})", 
                         entry.iat_address, entry.resolved_address, 
                         entry.import.dll_name(), entry.import.function_name());
            }
            
            log::info!("  Populated {} IAT entries", pe.iat_entries().len());
        } else {
            log::info!("  No IAT entries to populate");
        }
        
        Ok(())
    }
    
    fn setup_cpu_state(emu: &mut Unicorn<'static, ()>, pe: &LoadedPE) -> Result<(), uc_error> {
        log::info!("\n🖥️  Setting up CPU state:");
        
        // Set entry point
        emu.reg_write(RegisterX86::RIP, pe.entry_point())?;
        log::info!("  RIP: 0x{:016x}", pe.entry_point());
        
        // Set stack pointer
        let stack_pointer = 0x7fff0000 + 0x8000; // Middle of stack
        emu.reg_write(RegisterX86::RSP, stack_pointer)?;
        log::info!("  RSP: 0x{:016x}", stack_pointer);
        
        // Set up basic registers (Windows x64 ABI)
        emu.reg_write(RegisterX86::RBP, stack_pointer)?;
        
        // Clear other registers
        for &reg in &[RegisterX86::RAX, RegisterX86::RBX, RegisterX86::RCX, 
                      RegisterX86::RDX, RegisterX86::RSI, RegisterX86::RDI] {
            emu.reg_write(reg, 0)?;
        }
        
        Ok(())
    }
    
    pub fn run(&mut self, max_instructions: u64) -> Result<(), LoaderError> {
        log::info!("\n🚀 Starting execution at 0x{:016x}", self.loaded_pe.entry_point());
        
        // Set up hooks for debugging
        self.setup_hooks()?;
        
        // Execute with instruction limit
        let result = self.emu.emu_start(
            self.loaded_pe.entry_point(),
            0, // No specific end address
            0, // No timeout
            max_instructions as usize,
        );
        
        match result {
            Ok(_) => log::info!("✅ Execution completed successfully"),
            Err(e) => {
                let rip = self.emu.reg_read(RegisterX86::RIP)?;
                log::info!("❌ Execution stopped at 0x{:016x}: {:?}", rip, e);
                self.dump_cpu_state()?;
            }
        }
        
        Ok(())
    }
    
    fn setup_hooks(&mut self) -> Result<(), uc_error> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        
        // Just check if address is in the mock function range (0x7F000000 - 0x7F010000)
        const MOCK_FUNC_BASE: u64 = 0x7F000000;
        const MOCK_FUNC_END: u64 = 0x7F010000;
        
        let start_time = Instant::now();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);

        // Add instruction hook for debugging
        let _code_hook = self.emu.add_code_hook(0, u64::MAX, move |emu, addr, size| {
            let count = COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Check if we're about to execute in the mock IAT function range
            if addr >= MOCK_FUNC_BASE && addr < MOCK_FUNC_END {
                log::info!("🛑 STOPPING: About to execute IAT function at 0x{:016x}", addr);
                log::info!("   This is a mock IAT function - execution should not reach here!");
                panic!("IAT function reached at 0x{:016x}", addr);
            }
            
            // Read the instruction bytes
            let mut code_bytes = vec![0u8; size as usize];
            emu.mem_read(addr, &mut code_bytes).unwrap();
            
            // Disassemble the instruction
            let mut decoder = Decoder::with_ip(64, &code_bytes, addr, DecoderOptions::NONE);
            let instruction = decoder.decode();
            
            // Format the instruction
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            
            // Calculate instructions per second
            let elapsed = start_time.elapsed();
            let elapsed_secs = elapsed.as_secs_f64().max(0.000001); // Avoid divide by zero
            let ips = count as f64 / elapsed_secs;
            log::info!("  {:.0} ops/sec | [{}] 0x{:016x}: {}", 
                    ips, count, addr, output);
        })?;

        // Add memory access hook for debugging
        let _mem_hook = self.emu.add_mem_hook(
            unicorn_engine::unicorn_const::HookType::MEM_INVALID,
            0,
            u64::MAX,
            |_emu, mem_type, addr, size, value| {
                log::info!("❌ Invalid memory access: {:?} at 0x{:016x} (size: {}, value: 0x{:x})", 
                        mem_type, addr, size, value);
                false // Don't handle the error, let it propagate
            }
        )?;
        
        Ok(())
    }
    
    fn dump_cpu_state(&mut self) -> Result<(), uc_error> {
        log::info!("\n📊 CPU State:");
        
        let registers = [
            ("RIP", RegisterX86::RIP),
            ("RSP", RegisterX86::RSP),
            ("RBP", RegisterX86::RBP),
            ("RAX", RegisterX86::RAX),
            ("RBX", RegisterX86::RBX),
            ("RCX", RegisterX86::RCX),
            ("RDX", RegisterX86::RDX),
            ("RSI", RegisterX86::RSI),
            ("RDI", RegisterX86::RDI),
        ];
        
        for (name, reg) in registers {
            let value = self.emu.reg_read(reg)?;
            log::info!("  {}: 0x{:016x}", name, value);
        }
        
        // Show some memory around RIP
        let rip = self.emu.reg_read(RegisterX86::RIP)?;
        let mut code = vec![0u8; 16];
        if self.emu.mem_read(rip, &mut code).is_ok() {
            log::info!("  Code at RIP: {:02x?}", code);
        }
        
        Ok(())
    }
    
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.loaded_pe.symbols().get(name).copied()
    }
    
    pub fn get_imports(&self) -> &[ImportedFunction] {
        &self.loaded_pe.imports()
    }
    
    fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, uc_error> {
        let mut data = vec![0u8; size];
        self.emu.mem_read(addr, &mut data)?;
        Ok(data)
    }
    
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), uc_error> {
        self.emu.mem_write(addr, data)
    }
}
