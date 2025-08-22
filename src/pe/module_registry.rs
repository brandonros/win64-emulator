use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use unicorn_engine::{Permission, Unicorn};

use crate::pe::constants::{MOCK_FUNCTION_BASE, MOCK_FUNCTION_SIZE, MOCK_FUNCTION_SPACING, SYSTEM_DLL_BASE};
use crate::pe::LoadedPE;
use crate::emulation::iat::IAT_FUNCTION_MAP;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LoadedModule {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
    pub exports: HashMap<String, u64>,  // Export name -> address
}

impl LoadedModule {
    pub fn new(name: String, base_address: u64, size: u64) -> Self {
        Self {
            name,
            base_address,
            size,
            exports: HashMap::new(),
        }
    }
    
    pub fn with_exports(name: String, base_address: u64, size: u64, exports: HashMap<String, u64>) -> Self {
        Self {
            name,
            base_address,
            size,
            exports,
        }
    }
    
    pub fn get_proc_address(&self, function_name: &str) -> Option<u64> {
        self.exports.get(function_name).copied()
    }
}

// Global module registry
pub static MODULE_REGISTRY: LazyLock<RwLock<ModuleRegistry>> = LazyLock::new(|| {
    RwLock::new(ModuleRegistry::new())
});

pub struct ModuleRegistry {
    modules: HashMap<String, LoadedModule>,
    next_dll_base: u64,  // For dynamic allocation of DLL base addresses
    next_mock_addr: u64, // For dynamic allocation of mock function addresses
}

impl ModuleRegistry {
    fn new() -> Self {
        // Start with an empty registry - modules will be registered when actually loaded
        ModuleRegistry {
            modules: HashMap::new(),
            next_dll_base: SYSTEM_DLL_BASE,
            next_mock_addr: MOCK_FUNCTION_BASE + 0x1000, // Leave some space at the beginning
        }
    }
    
    pub fn allocate_base_address(&mut self, size: u64) -> u64 {
        let base = self.next_dll_base;
        // This could potentially allocate addresses that conflict with MAIN_MODULE_BASE
        self.next_dll_base += ((size + 0xFFFF) & !0xFFFF) + 0x10000;
        base
    }

    // Allocate a mock function address for hook interception
    pub fn allocate_mock_address(&mut self) -> u64 {
        let addr = self.next_mock_addr;
        self.next_mock_addr += MOCK_FUNCTION_SPACING;
        if addr >= MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64 {
            panic!("Mock function address space exhausted! Need to map more memory.");
        }
        addr
    }
    
    pub fn get_module_handle(&self, name: Option<&str>) -> Option<u64> {
        match name {
            None => {
                // NULL means main module - look it up from registered modules
                self.modules.get("main")
                    .map(|m| m.base_address)
            },
            Some(module_name) => {
                let normalized = module_name.to_lowercase();
                self.modules.get(&normalized)
                    .map(|m| m.base_address)
            }
        }
    }
    
    pub fn register_main_module(&mut self, emu: &mut Unicorn<()>, pe_path: &str, base: u64, size: u64) {
        self.modules.insert(
            "main".to_string(),
            LoadedModule::new(
                "main".to_string(),
                base,
                size,
            )
        );

        // load the module into memory
        let pe_bytes = std::fs::read(pe_path).unwrap(); // TODO: not unwrap
        emu.mem_map(base, size as usize, Permission::ALL).unwrap(); // TODO: not unwrap
        emu.mem_write(base, &pe_bytes).unwrap(); // TODO: not unwrap
    }
    
    pub fn register_module_with_exports(&mut self, name: &str, base: u64, size: u64, exports: HashMap<String, u64>) {
        let normalized_name = name.to_lowercase();
        self.modules.insert(
            normalized_name.clone(),
            LoadedModule::with_exports(
                normalized_name.clone(),
                base,
                size,
                exports,
            )
        );
        
        // Also register without .dll extension
        if normalized_name.ends_with(".dll") {
            let without_ext = normalized_name.trim_end_matches(".dll");
            // Clone the module with same exports
            let module = self.modules.get(&normalized_name).unwrap().clone();
            self.modules.insert(without_ext.to_string(), module);
        }
    }
    
    pub fn get_loaded_module_by_module_base(&self, module_base: u64) -> Option<&LoadedModule> {
        // Find module by base address
        for module in self.modules.values() {
            if module.base_address == module_base {
                return Some(module);
            }
        }
        None
    }

    // Helper function to load and register a system DLL with mock exports
    pub fn load_system_dll(&mut self, emu: &mut Unicorn<()>, dll_path: &str, dll_name: &str) -> Result<(), String> {
        // Try to load the DLL
        let dll_pe = LoadedPE::from_file(dll_path)
            .map_err(|e| format!("Failed to load {}: {:?}", dll_name, e))?;
        let dll_pe_bytes = dll_pe.loaded_bytes();
        let image_size = dll_pe.image_size() as u64;
        let file_size = dll_pe_bytes.len() as u64;
        let actual_size = std::cmp::max(image_size, file_size);
        let mapped_size = ((actual_size + 0xFFF) & !0xFFF) as usize;
        
        log::info!("📚 Loaded {} with {} exports", dll_name, dll_pe.exports().len());
        
        // Allocate base address for the DLL
        let base_addr = self.allocate_base_address(mapped_size as u64);

        // Load the DLL into memory
        emu.mem_map(base_addr, mapped_size, Permission::ALL).unwrap(); // TODO: not unwrap
        emu.mem_write(base_addr, &dll_pe_bytes).unwrap(); // TODO: not unwrap
        
        // Build export map with mock addresses for hook interception
        let mut dll_exports = HashMap::new();
        
        // Also update the IAT function map so hooks know what to call
        let mut iat_map = IAT_FUNCTION_MAP.write().unwrap();
        
        for (name, _export) in dll_pe.exports() {
            let mock_addr = self.allocate_mock_address();
            dll_exports.insert(name.clone(), mock_addr);
            
            // Add to IAT function map for hook interception
            iat_map.insert(
                mock_addr,
                (dll_name.to_string(), name.clone())
            );
            
            log::info!("  {}!{} -> 0x{:x}", dll_name, name, mock_addr);
        }
        
        // Register the module with its exports
        self.register_module_with_exports(dll_name, base_addr, image_size, dll_exports); // image_size, not mapped_size
        log::info!("  Registered {} at base 0x{:x}", dll_name, base_addr);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use unicorn_engine::{Arch, Mode};

    use super::*;

    #[test]
    fn test_ole32_exports_coinitializeex() {
        // Create an emulator
        let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();

        // Initialize the module registry
        let mut registry = MODULE_REGISTRY.write().unwrap();
        
        // Determine the path to ole32.dll
        let ole32_path = "./assets/ole32.dll";
        
        // Load ole32.dll
        let result = registry.load_system_dll(&mut emu, ole32_path, "ole32.dll");
        assert!(result.is_ok(), "Failed to load ole32.dll: {:?}", result.err());
        
        // Get the loaded module
        let module = registry.get_loaded_module_by_module_base(
            registry.get_module_handle(Some("ole32.dll")).expect("ole32.dll should be loaded")
        ).expect("Should find ole32.dll module");

        println!("{:?}", module.exports);
        
        // Verify that CoInitializeEx is exported
        assert!(
            module.exports.contains_key("CoInitializeEx"),
            "ole32.dll should export CoInitializeEx function"
        );
        
        // Optionally verify the mock address was allocated
        let coinit_addr = module.get_proc_address("CoInitializeEx");
        assert!(coinit_addr.is_some(), "Should be able to get CoInitializeEx address");
        
        let addr = coinit_addr.unwrap();
        assert!(
            addr >= MOCK_FUNCTION_BASE && addr < MOCK_FUNCTION_BASE + 0x1000000,
            "CoInitializeEx should have a valid mock address: 0x{:x}",
            addr
        );
        
        // Verify it was registered in the IAT function map
        let iat_map = IAT_FUNCTION_MAP.read().unwrap();
        assert!(
            iat_map.contains_key(&addr),
            "CoInitializeEx should be registered in IAT function map"
        );
        
        let (dll_name, func_name) = iat_map.get(&addr).unwrap();
        assert_eq!(dll_name, "ole32.dll");
        assert_eq!(func_name, "CoInitializeEx");
    }
}