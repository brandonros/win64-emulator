use unicorn_engine::{uc_error, Arch, Mode, RegisterX86, Unicorn};
use crate::loader_error::LoaderError;
use crate::pe::{ImportedFunction, LoadedPE, MODULE_REGISTRY};

pub mod memory;
mod cpu;
pub mod iat;
mod hooks;

pub struct Emulator {
    emu: Unicorn<'static, ()>,
    loaded_pe: LoadedPE,
}

impl Emulator {
    pub fn new(pe_path: &str) -> Result<Self, LoaderError> {
        // Load the main PE
        let loaded_pe = LoadedPE::from_file(pe_path)?;

        // Register the main module in the module registry
        {
            let mut registry = MODULE_REGISTRY.write().unwrap();
            registry.register_main_module(loaded_pe.image_base(), loaded_pe.image_size() as u64);
        }

        // Load system DLLs
        {
            let mut registry = MODULE_REGISTRY.write().unwrap();
            registry.load_system_dll("./assets/kernel32.dll", "kernel32.dll")?;
            registry.load_system_dll("./assets/ntdll.dll", "ntdll.dll")?;
            registry.load_system_dll("./assets/user32.dll", "user32.dll")?;
            registry.load_system_dll("./assets/advapi32.dll", "advapi32.dll")?;
            registry.load_system_dll("./assets/oleaut32.dll", "oleaut32.dll")?;
            registry.load_system_dll("./assets/gdi32.dll", "gdi32.dll")?;
            registry.load_system_dll("./assets/shell32.dll", "shell32.dll")?;
            registry.load_system_dll("./assets/version.dll", "version.dll")?;
            registry.load_system_dll("./assets/ole32.dll", "ole32.dll")?;
            registry.load_system_dll("./assets/vcruntime140.dll", "vcruntime140.dll")?;
            registry.load_system_dll("./assets/shlwapi.dll", "shlwapi.dll")?;            
            registry.load_system_dll("./assets/comctl32.dll", "comctl32.dll")?;                        
            registry.load_system_dll("./assets/psapi.dll", "psapi.dll")?;                                    
            registry.load_system_dll("./assets/api-ms-win-core-synch-l1-2-0.dll", "api-ms-win-core-synch-l1-2-0.dll")?;
            registry.load_system_dll("./assets/api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll")?;
            registry.load_system_dll("./assets/api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-math-l1-1-0.dll")?;
            registry.load_system_dll("./assets/api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll")?;
            registry.load_system_dll("./assets/api-ms-win-crt-locale-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll")?;
            registry.load_system_dll("./assets/api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll")?;
        }

        let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)?;
        
        // Set up memory regions for the PE
        memory::setup_memory(&mut emu, &loaded_pe)?;
        
        // Set up TEB and PEB structures for Windows compatibility
        memory::setup_teb(&mut emu)?;
        memory::setup_peb(&mut emu, loaded_pe.image_base())?;
        
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
            self::hooks::memory_hook_callback
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