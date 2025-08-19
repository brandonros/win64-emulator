use std::collections::HashMap;
use unicorn_engine::{uc_error, Arch, Mode, RegisterX86, Unicorn};
use crate::loader_error::LoaderError;
use crate::pe::{LoadedPE, ImportedFunction};
use crate::winapi::module_registry::MODULE_REGISTRY;

pub mod memory;
mod cpu;
mod iat;
mod hooks;
pub struct Emulator {
    emu: Unicorn<'static, ()>,
    loaded_pe: LoadedPE,
}

impl Emulator {
    pub fn new(pe_path: &str) -> Result<Self, LoaderError> {
        // register kernel32
        let kernel32_pe = LoadedPE::from_file("./assets/kernel32.dll")?;
        {
            let mut registry = MODULE_REGISTRY.write().unwrap();
            let base_addr = registry.allocate_base_address(0x100000);
            let mut kernel32_exports = HashMap::new();
            for (name, _export) in kernel32_pe.exports() {
                let mock_addr = registry.allocate_mock_address();
                kernel32_exports.insert(name.clone(), mock_addr);
                log::debug!("  kernel32!{} -> 0x{:x}", name, mock_addr);
            }
            registry.register_module_with_exports(
                "kernel32.dll",
                base_addr,
                0x100000,
                kernel32_exports
            );
        }

        // Now load the main PE
        let loaded_pe = LoadedPE::from_file(pe_path)?;
        
        // Register the main module in the module registry
        {
            let mut registry = MODULE_REGISTRY.write().unwrap();
            registry.register_main_module(loaded_pe.image_base(), loaded_pe.image_size() as u64);
        }

        let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)?;
        
        // Set up memory regions for the PE
        memory::setup_memory(&mut emu, &loaded_pe)?;
        
        // Populate IAT with mock function addresses
        iat::setup_iat(&mut emu, &loaded_pe)?;
        
        // Set up initial CPU state
        cpu::setup_cpu_state(&mut emu, &loaded_pe)?;
        
        Ok(Emulator { emu, loaded_pe })
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
                cpu::dump_cpu_state(&mut self.emu)?;
            }
        }
        
        Ok(())
    }
    
    fn setup_hooks(&mut self) -> Result<(), uc_error> {
        // Add instruction hook for debugging
        let _code_hook = self.emu.add_code_hook(0, u64::MAX, self::hooks::code_hook_callback)?;

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
    
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.loaded_pe.symbols().get(name).copied()
    }
    
    pub fn get_imports(&self) -> &[ImportedFunction] {
        &self.loaded_pe.imports()
    }
}