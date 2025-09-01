use unicorn_engine::{uc_error, Arch, Mode, RegisterX86, Unicorn};
use crate::loader_error::LoaderError;
use crate::pe::module_registry::MODULE_REGISTRY;
use crate::pe::{ImportedFunction, LoadedPE};

pub mod memory;
mod cpu;
pub mod iat;
mod hooks;
//mod iat_hooks;
pub mod vfs;
#[cfg(feature = "trace-instruction")]
pub mod tracing;

pub struct Emulator {
    emu: Unicorn<'static, ()>,
    loaded_pe: LoadedPE,
    is_dll: bool,
}

impl Emulator {
    pub fn new(pe_path: &str) -> Result<Self, LoaderError> {
        // Create the emulator
        let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)?;

        // Load the main PE
        let loaded_pe = LoadedPE::from_file(pe_path)?;
        
        // Detect if this is a DLL
        let is_dll = pe_path.to_lowercase().ends_with(".dll");

        // Load system DLLs
        {
            MODULE_REGISTRY.load_system_dll(&mut emu, "./target/x86_64-pc-windows-gnu/debug/ntdll.dll", "ntdll.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./target/x86_64-pc-windows-gnu/debug/kernel32.dll", "kernel32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/kernelbase.dll", "kernelbase.dll", None)?;            
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/psapi.dll", "psapi.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/user32.dll", "user32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/advapi32.dll", "advapi32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/oleaut32.dll", "oleaut32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/gdi32.dll", "gdi32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/shell32.dll", "shell32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/version.dll", "version.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/ole32.dll", "ole32.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/vcruntime140.dll", "vcruntime140.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/shlwapi.dll", "shlwapi.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/comctl32.dll", "comctl32.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-core-synch-l1-2-0.dll", "api-ms-win-core-synch-l1-2-0.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-math-l1-1-0.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-crt-locale-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll", None)?;
            MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/shfolder.dll", "shfolder.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/msimg32.dll", "msimg32.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/dwmapi.dll", "dwmapi.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/uxtheme.dll", "uxtheme.dll", None)?;
            // MODULE_REGISTRY.load_system_dll(&mut emu, "./assets/win32u.dll", "win32u.dll", None)?;                                
        }

        // Register the main module in the module registry
        {
            MODULE_REGISTRY.register_main_module(&mut emu, &loaded_pe, pe_path);
        }
        
        // Set up memory regions for the PE
        memory::setup_memory(&mut emu, &loaded_pe)?;
        
        // Set up TEB and PEB structures for Windows compatibility
        memory::setup_teb(&mut emu)?;
        memory::setup_peb(&mut emu, loaded_pe.image_base())?;
        
        // Populate IAT with mock function addresses
        iat::setup_iat(&mut emu, &loaded_pe)?;
        
        // Patch IAT with actual DLL exports now that all DLLs are loaded
        iat::patch_iat(&mut emu, &loaded_pe)?;
        
        // Set up initial CPU state based on PE type
        if is_dll {
            // For DLLs, set up with DLL_PROCESS_ATTACH
            cpu::setup_dll_cpu_state(&mut emu, &loaded_pe, crate::pe::constants::DLL_PROCESS_ATTACH)?;
        } else {
            // For EXEs, use regular setup
            cpu::setup_cpu_state(&mut emu, &loaded_pe)?;
        }
        
        Ok(Emulator { emu, loaded_pe, is_dll })
    }
    
    pub fn run(&mut self, max_instructions: u64) -> Result<(), LoaderError> {
        let entry_type = if self.is_dll { "DllMain" } else { "entry point" };
        log::info!("\n🚀 Starting execution at 0x{:016x} ({})", self.loaded_pe.entry_point(), entry_type);
        
        if self.is_dll {
            log::info!("📦 Executing DLL with DLL_PROCESS_ATTACH");
        }
        
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
            Ok(_) => {
                if self.is_dll {
                    // Check RAX for DllMain return value
                    let rax = self.emu.reg_read(RegisterX86::RAX)?;
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
                let rip = self.emu.reg_read(RegisterX86::RIP)?;
                log::info!("❌ Execution stopped at 0x{:016x}: {:?}", rip, e);
                cpu::dump_cpu_state(&mut self.emu)?;
            }
        }
        
        Ok(())
    }
    
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }
    
    fn setup_hooks(&mut self) -> Result<(), uc_error> {
        // Add instruction hook for debugging
        let _code_hook = self.emu.add_code_hook(0, u64::MAX, self::hooks::code_hook_callback)?;

        // Add memory access hook for debugging
        let _mem_read_hook = self.emu.add_mem_hook(
            unicorn_engine::unicorn_const::HookType::MEM_READ_AFTER,
            0,
            u64::MAX,
            self::hooks::memory_read_hook_callback
        )?;
        let _mem_write_hook = self.emu.add_mem_hook(
            unicorn_engine::unicorn_const::HookType::MEM_WRITE,
            0,
            u64::MAX,
            self::hooks::memory_write_hook_callback
        )?;
        let _mem_invalid_hook = self.emu.add_mem_hook(
            unicorn_engine::unicorn_const::HookType::MEM_INVALID,
            0,
            u64::MAX,
            self::hooks::memory_invalid_hook_callback
        )?;
        
        Ok(())
    }
    
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.loaded_pe.symbols().get(name).copied()
    }

    pub fn get_imports(&self) -> &[ImportedFunction] {
        &self.loaded_pe.imports()
    }

    pub fn get_emu(&self) -> &Unicorn<'static, ()> {
        &self.emu
    }
}