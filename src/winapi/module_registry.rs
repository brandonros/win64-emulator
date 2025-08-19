use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

// Mock base addresses for system DLLs
pub const KERNEL32_BASE: u64 = 0x7FF800000000;
pub const NTDLL_BASE: u64 = 0x7FF900000000;
pub const USER32_BASE: u64 = 0x7FF700000000;
pub const GDI32_BASE: u64 = 0x7FF600000000;
pub const ADVAPI32_BASE: u64 = 0x7FF500000000;
pub const OLEAUT32_BASE: u64 = 0x7FF400000000;
pub const SHELL32_BASE: u64 = 0x7FF300000000;
pub const VERSION_BASE: u64 = 0x7FF200000000;
pub const OLE32_BASE: u64 = 0x7FF100000000;
pub const VCRUNTIME140_BASE: u64 = 0x7FF000000000;
pub const API_MS_WIN_CORE_SYNCH_BASE: u64 = 0x7FEF00000000;
pub const API_MS_WIN_CRT_RUNTIME_BASE: u64 = 0x7FEE00000000;
pub const API_MS_WIN_CRT_MATH_BASE: u64 = 0x7FED00000000;
pub const API_MS_WIN_CRT_STDIO_BASE: u64 = 0x7FEC00000000;
pub const API_MS_WIN_CRT_LOCALE_BASE: u64 = 0x7FEB00000000;
pub const API_MS_WIN_CRT_HEAP_BASE: u64 = 0x7FEA00000000;

// Main executable base (standard Windows x64)
pub const MAIN_MODULE_BASE: u64 = 0x140000000;

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
        registry.register_module("advapi32.dll", ADVAPI32_BASE, 0x100000);
        registry.register_module("oleaut32.dll", OLEAUT32_BASE, 0x80000);
        registry.register_module("shell32.dll", SHELL32_BASE, 0x180000);
        registry.register_module("version.dll", VERSION_BASE, 0x20000);
        registry.register_module("ole32.dll", OLE32_BASE, 0x100000);
        registry.register_module("vcruntime140.dll", VCRUNTIME140_BASE, 0x20000);
        registry.register_module("api-ms-win-core-synch-l1-2-0.dll", API_MS_WIN_CORE_SYNCH_BASE, 0x10000);
        registry.register_module("api-ms-win-crt-runtime-l1-1-0.dll", API_MS_WIN_CRT_RUNTIME_BASE, 0x10000);
        registry.register_module("api-ms-win-crt-math-l1-1-0.dll", API_MS_WIN_CRT_MATH_BASE, 0x10000);
        registry.register_module("api-ms-win-crt-stdio-l1-1-0.dll", API_MS_WIN_CRT_STDIO_BASE, 0x10000);
        registry.register_module("api-ms-win-crt-locale-l1-1-0.dll", API_MS_WIN_CRT_LOCALE_BASE, 0x10000);
        registry.register_module("api-ms-win-crt-heap-l1-1-0.dll", API_MS_WIN_CRT_HEAP_BASE, 0x10000);
        
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
}