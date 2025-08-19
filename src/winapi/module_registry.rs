use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

// Mock base addresses for system DLLs
pub const KERNEL32_BASE: u64 = 0x7FF800000000;
pub const NTDLL_BASE: u64 = 0x7FF900000000;
pub const USER32_BASE: u64 = 0x7FF700000000;
pub const GDI32_BASE: u64 = 0x7FF600000000;

// Main executable base (standard Windows x64)
pub const MAIN_MODULE_BASE: u64 = 0x140000000;

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub base_address: u64,
    pub size: u64,
}

impl LoadedModule {
    pub fn new(name: String, base_address: u64, size: u64) -> Self {
        Self {
            name,
            base_address,
            size,
        }
    }
}

// Global module registry
pub static MODULE_REGISTRY: Lazy<RwLock<ModuleRegistry>> = Lazy::new(|| {
    RwLock::new(ModuleRegistry::new())
});

pub struct ModuleRegistry {
    modules: HashMap<String, LoadedModule>,
}

impl ModuleRegistry {
    fn new() -> Self {
        let mut registry = ModuleRegistry {
            modules: HashMap::new(),
        };
        
        // Pre-register common system DLLs
        registry.register_module("kernel32.dll", KERNEL32_BASE, 0x100000);
        registry.register_module("ntdll.dll", NTDLL_BASE, 0x200000);
        registry.register_module("user32.dll", USER32_BASE, 0x100000);
        registry.register_module("gdi32.dll", GDI32_BASE, 0x80000);
        
        registry
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
}