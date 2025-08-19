use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use crate::pe::LoadedPE;

// Main executable base (standard Windows x64)
pub const MAIN_MODULE_BASE: u64 = 0x140000000;

// Base address for system DLLs (they'll be allocated sequentially from here)
pub const SYSTEM_DLL_BASE: u64 = 0x7FF000000000;

// Base address for mock functions (for hook interception)
pub const MOCK_FUNCTION_BASE: u64 = 0x7F000000;
pub const MOCK_FUNCTION_SPACING: u64 = 0x10;

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
    
    // Allocate a base address for a new DLL
    pub fn allocate_base_address(&mut self, size: u64) -> u64 {
        let base = self.next_dll_base;
        // Align to 64KB boundary and leave some space
        self.next_dll_base += ((size + 0xFFFF) & !0xFFFF) + 0x10000;
        base
    }
    
    // Allocate a mock function address for hook interception
    pub fn allocate_mock_address(&mut self) -> u64 {
        let addr = self.next_mock_addr;
        self.next_mock_addr += MOCK_FUNCTION_SPACING;
        addr
    }
    
    pub fn register_module(&mut self, name: &str, base: u64, size: u64) {
        let normalized_name = name.to_lowercase();
        self.modules.insert(
            normalized_name.clone(),
            LoadedModule::new(
                normalized_name.clone(),
                base,
                size,
            )
        );
        
        // Also register without .dll extension
        if normalized_name.ends_with(".dll") {
            let without_ext = normalized_name.trim_end_matches(".dll");
            self.modules.insert(
                without_ext.to_string(),
                LoadedModule::new(
                    normalized_name.clone(),
                    base,
                    size,
                )
            );
        }
    }
    
    pub fn get_module_handle(&self, name: Option<&str>) -> Option<u64> {
        match name {
            None => Some(MAIN_MODULE_BASE), // NULL means main module
            Some(module_name) => {
                let normalized = module_name.to_lowercase();
                self.modules.get(&normalized)
                    .map(|m| m.base_address)
            }
        }
    }
    
    pub fn register_main_module(&mut self, base: u64, size: u64) {
        self.modules.insert(
            "main".to_string(),
            LoadedModule::new(
                "main".to_string(),
                base,
                size,
            )
        );
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
    
    pub fn get_proc_address(&self, module_base: u64, function_name: &str) -> Option<u64> {
        // Find module by base address
        for module in self.modules.values() {
            if module.base_address == module_base {
                // Look up function in exports
                return module.exports.get(function_name).copied();
            }
        }
        None
    }
    
    pub fn add_export_to_module(&mut self, module_name: &str, function_name: &str, address: u64) {
        let normalized_name = module_name.to_lowercase();
        if let Some(module) = self.modules.get_mut(&normalized_name) {
            module.exports.insert(function_name.to_string(), address);
        }
    }
    
    // Helper function to load and register a system DLL with mock exports
    pub fn load_system_dll(&mut self, dll_path: &str, dll_name: &str, size: u64) -> Result<(), String> {
        // Try to load the DLL
        let dll_pe = LoadedPE::from_file(dll_path)
            .map_err(|e| format!("Failed to load {}: {:?}", dll_name, e))?;
        
        log::info!("📚 Loaded {} with {} exports", dll_name, dll_pe.exports().len());
        
        // Allocate base address for the DLL
        let base_addr = self.allocate_base_address(size);
        
        // Build export map with mock addresses for hook interception
        let mut dll_exports = HashMap::new();
        for (name, _export) in dll_pe.exports() {
            let mock_addr = self.allocate_mock_address();
            dll_exports.insert(name.clone(), mock_addr);
            log::debug!("  {}!{} -> 0x{:x}", dll_name, name, mock_addr);
        }
        
        // Register the module with its exports
        self.register_module_with_exports(dll_name, base_addr, size, dll_exports);
        log::info!("  Registered {} at base 0x{:x}", dll_name, base_addr);
        
        Ok(())
    }
}