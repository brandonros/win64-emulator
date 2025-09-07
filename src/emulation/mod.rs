use std::path::Path;

use unicorn_engine::{Unicorn, Arch, Mode};
use crate::loader_error::LoaderError;
use crate::pe::{ImportedFunction, LoadedPE, MODULE_REGISTRY};
use crate::emulation::engine::{EmulatorEngine, X86Register};
use crate::emulation::unicorn_backend::UnicornEngine;

pub mod memory;
mod cpu;
pub mod iat;
mod memory_hooks;
mod code_hooks;
mod iat_hooks;
pub mod vfs;
pub mod dump;
#[cfg(feature = "trace-instruction")]
pub mod tracing;
pub mod engine;
pub mod unicorn_backend;

pub struct Emulator {
    emu: Box<dyn EmulatorEngine>,
    loaded_pe: LoadedPE,
    is_dll: bool,
}

impl Emulator {
    pub fn new(pe_path: &str) -> Result<Self, LoaderError> {
        // Create the Unicorn emulator
        let unicorn = Unicorn::new(Arch::X86, Mode::MODE_64)?;
        let mut emu_engine = UnicornEngine::from_unicorn(unicorn);
        
        // Load the main PE
        let loaded_pe = LoadedPE::from_file(pe_path)?;
        
        // Detect if this is a DLL
        let is_dll = pe_path.to_lowercase().ends_with(".dll");

        // Use the inner Unicorn for module registry (temporarily)
        let emu = emu_engine.inner();
        
        // Register the main module in the module registry
        MODULE_REGISTRY.register_main_module(emu, &loaded_pe, pe_path);

        // Load system DLLs
        MODULE_REGISTRY.load_system_dll(emu, "./assets/ntdll.dll", "ntdll.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/kernel32.dll", "kernel32.dll", Some(0x00007ff0001f8000))?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/kernelbase.dll", "kernelbase.dll", None)?;            
        MODULE_REGISTRY.load_system_dll(emu, "./assets/psapi.dll", "psapi.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/user32.dll", "user32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/advapi32.dll", "advapi32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/oleaut32.dll", "oleaut32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/gdi32.dll", "gdi32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/shell32.dll", "shell32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/version.dll", "version.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/ole32.dll", "ole32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/vcruntime140.dll", "vcruntime140.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/shlwapi.dll", "shlwapi.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/comctl32.dll", "comctl32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/msvcrt.dll", "msvcrt.dll", None)?;        
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-core-synch-l1-2-0.dll", "api-ms-win-core-synch-l1-2-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-math-l1-1-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-crt-locale-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/shfolder.dll", "shfolder.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/msimg32.dll", "msimg32.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/dwmapi.dll", "dwmapi.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/uxtheme.dll", "uxtheme.dll", None)?;
        MODULE_REGISTRY.load_system_dll(emu, "./assets/win32u.dll", "win32u.dll", None)?;                                
        
        // Set up memory regions for the PE
        memory::setup_memory(emu, &loaded_pe)?;
        
        // Set up TEB and PEB structures for Windows compatibility
        memory::setup_teb(emu)?;
        memory::setup_peb(emu, loaded_pe.image_base())?;
        
        // Populate IAT with mock function addresses
        iat::setup_iat(emu, &loaded_pe)?;
        
        // Set up initial CPU state based on PE type
        if is_dll {
            // For DLLs, set up with DLL_PROCESS_ATTACH
            cpu::setup_dll_cpu_state(&mut emu_engine as &mut dyn EmulatorEngine, &loaded_pe, crate::pe::constants::DLL_PROCESS_ATTACH)?;
        } else {
            // For EXEs, use regular setup
            cpu::setup_cpu_state(&mut emu_engine as &mut dyn EmulatorEngine, &loaded_pe)?;
        }
        
        let mut emulator = Emulator { 
            emu: Box::new(emu_engine), 
            loaded_pe, 
            is_dll 
        };
        
        // Register the global engine pointer for fast hooks - AFTER boxing
        unsafe {
            // Get a stable pointer to the boxed engine
            let engine_ptr = emulator.emu.as_mut() as *mut dyn EmulatorEngine as *mut UnicornEngine;
            code_hooks::register_global_engine(engine_ptr);
        }
        
        Ok(emulator)
    }
    
    pub fn run(&mut self, max_instructions: u64) -> Result<(), LoaderError> {
        let entry_type = if self.is_dll { "DllMain" } else { "entry point" };
        log::info!("\n🚀 Starting execution at 0x{:016x} ({})", self.loaded_pe.entry_point(), entry_type);
        
        if self.is_dll {
            log::info!("📦 Executing DLL with DLL_PROCESS_ATTACH");
        }
        
        // Set up hooks for debugging
        log::info!("Setting up hooks");
        self.setup_code_hooks()?;
        self.setup_memory_hooks()?;    
        log::info!("Set up hooks");
        
        // Execute with instruction limit
        let result = self.emu.emu_start(
            self.loaded_pe.entry_point(),
            0, // No specific end address
            0, // No timeout
            max_instructions as usize,
        );
        
        match result {
            Ok(_) => {
                if self.is_dll {
                    // Check RAX for DllMain return value
                    let rax = self.emu.reg_read(X86Register::RAX)?;
                    if rax != 0 {
                        log::info!("✅ DllMain returned TRUE (0x{:x})", rax);
                    } else {
                        log::info!("⚠️  DllMain returned FALSE (0x{:x})", rax);
                    }
                } else {
                    log::info!("✅ Execution completed successfully");
                }
            },
            Err(e) => {
                let rip = self.emu.reg_read(X86Register::RIP)?;
                log::info!("❌ Execution stopped at 0x{:016x}: {:?}", rip, e);
                cpu::dump_cpu_state(self.emu.as_mut())?;

                // dump
                dump::dump_memory(self.emu.as_mut(), Path::new("/tmp/dump"))?;
            }
        }
        
        Ok(())
    }
    
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }
    
    fn setup_code_hooks(&mut self) -> Result<(), LoaderError> {
        // For now, we need to use Unicorn directly for hooks
        if let Some(uc) = self.emu.as_unicorn() {
            let _code_hook = uc.add_code_hook(0, u64::MAX, self::code_hooks::code_hook_callback_unicorn)
                .map_err(|e| LoaderError::Other(format!("Failed to add code hook: {:?}", e)))?;
        }
        Ok(())
    }

    fn setup_memory_hooks(&mut self) -> Result<(), LoaderError> {
        use unicorn_engine::HookType;
        
        if let Some(uc) = self.emu.as_unicorn() {
            if cfg!(feature = "log-mem-read") {
                let _mem_read_hook = uc.add_mem_hook(
                    HookType::MEM_READ_AFTER,
                    0,
                    u64::MAX,
                    self::memory_hooks::memory_read_hook_callback_unicorn
                ).map_err(|e| LoaderError::Other(format!("Failed to add mem read hook: {:?}", e)))?;
            }

            if cfg!(feature = "log-mem-write") {
                let _mem_write_hook = uc.add_mem_hook(
                    HookType::MEM_WRITE,
                    0,
                    u64::MAX,
                    self::memory_hooks::memory_write_hook_callback_unicorn
                ).map_err(|e| LoaderError::Other(format!("Failed to add mem write hook: {:?}", e)))?;
            }
            
            let _mem_invalid_hook = uc.add_mem_hook(
                HookType::MEM_INVALID,
                0,
                u64::MAX,
                self::memory_hooks::memory_invalid_hook_callback_unicorn
            ).map_err(|e| LoaderError::Other(format!("Failed to add mem invalid hook: {:?}", e)))?;
        }
        
        Ok(())
    }
    
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.loaded_pe.symbols().get(name).copied()
    }

    pub fn get_imports(&self) -> &[ImportedFunction] {
        &self.loaded_pe.imports()
    }
    
    pub fn get_memory_regions(&mut self) -> Result<Vec<(u64, u64)>, LoaderError> {
        self.emu.mem_regions()
            .map_err(|e| e.into())
    }

}


