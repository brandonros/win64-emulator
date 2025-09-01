use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};
use unicorn_engine::{Context, Unicorn};

use crate::loader_error::LoaderError;
use crate::emulation::memory::{STACK_BASE, STACK_SIZE, HEAP_BASE, HEAP_SIZE};
use crate::emulation::vfs::FileHandle;
use crate::pe::module_registry::LoadedModule;

#[derive(Serialize, Deserialize, Clone)]
pub struct EmulatorSnapshot {
    // Memory regions
    stack_memory: Vec<u8>,
    heap_memory: Vec<u8>,
    pe_memory: HashMap<u64, Vec<u8>>, // base_address -> memory contents
    
    // State managers
    heap_state: HeapManagerState,
    vfs_state: VfsState,
    module_registry_state: ModuleRegistryState,
    
    // Additional metadata
    instruction_count: u64,
    snapshot_name: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct HeapManagerState {
    next_addr: u64,
    allocations: HashMap<u64, usize>,
}

#[derive(Serialize, Deserialize, Clone)]
struct VfsState {
    handles: HashMap<u64, FileHandleState>,
    next_handle: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct FileHandleState {
    handle: u64,
    filename: String,
    access_mode: u32,
    share_mode: u32,
    creation_flags: u32,
    position: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct ModuleRegistryState {
    modules: HashMap<String, ModuleState>,
    next_dll_base: u64,
    next_mock_addr: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct ModuleState {
    name: String,
    base_address: u64,
    size: u64,
    exports: HashMap<String, u64>,
}

impl EmulatorSnapshot {
    pub fn capture(
        emu: &mut Unicorn<'static, ()>,
        snapshot_name: String,
        instruction_count: u64,
    ) -> Result<(Self, Context), LoaderError> {
        // Save CPU context using Unicorn's built-in functionality
        let cpu_context = emu.context_init()
            .map_err(|e| LoaderError::UnicornError(e))?;
        
        // Capture memory regions
        let stack_memory = Self::read_memory_region(emu, STACK_BASE, STACK_SIZE)?;
        let heap_memory = Self::read_memory_region(emu, HEAP_BASE, HEAP_SIZE)?;
        
        // Capture PE memory regions from MODULE_REGISTRY
        let pe_memory = Self::capture_pe_memory(emu)?;
        
        // Capture state managers
        let heap_state = Self::capture_heap_state();
        let vfs_state = Self::capture_vfs_state();
        let module_registry_state = Self::capture_module_registry_state();
        
        let snapshot = EmulatorSnapshot {
            stack_memory,
            heap_memory,
            pe_memory,
            heap_state,
            vfs_state,
            module_registry_state,
            instruction_count,
            snapshot_name,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        Ok((snapshot, cpu_context))
    }
    
    pub fn restore(
        &self,
        emu: &mut Unicorn<'static, ()>,
        cpu_context: &Context,
    ) -> Result<(), LoaderError> {
        // Restore CPU context
        emu.context_restore(cpu_context)
            .map_err(|e| LoaderError::UnicornError(e))?;
        
        // Restore memory regions
        Self::write_memory_region(emu, STACK_BASE, &self.stack_memory)?;
        Self::write_memory_region(emu, HEAP_BASE, &self.heap_memory)?;
        
        // Restore PE memory regions
        for (base_addr, memory) in &self.pe_memory {
            Self::write_memory_region(emu, *base_addr, memory)?;
        }
        
        // Restore state managers
        Self::restore_heap_state(&self.heap_state);
        Self::restore_vfs_state(&self.vfs_state);
        Self::restore_module_registry_state(&self.module_registry_state);
        
        log::info!("✅ Restored snapshot '{}' from timestamp {}", 
            self.snapshot_name, self.timestamp);
        
        Ok(())
    }
    
    pub fn save_to_disk(&self, cpu_context: &Context, path: &Path) -> Result<(), LoaderError> {
        // Create a combined structure that includes both snapshot and context
        let snapshot_file = SnapshotFile {
            snapshot: self.clone(),
            cpu_context_data: Self::serialize_context(cpu_context)?,
        };
        
        let mut file = File::create(path)
            .map_err(|e| LoaderError::IoError(e))?;
        
        let serialized = bincode::serialize(&snapshot_file)
            .map_err(|e| LoaderError::Other(format!("Serialization error: {}", e)))?;
        
        file.write_all(&serialized)
            .map_err(|e| LoaderError::IoError(e))?;
        
        log::info!("💾 Saved snapshot to {:?} ({} bytes)", path, serialized.len());
        Ok(())
    }
    
    pub fn load_from_disk(
        emu: &mut Unicorn<'static, ()>,
        path: &Path,
    ) -> Result<(Self, Context), LoaderError> {
        let mut file = File::open(path)
            .map_err(|e| LoaderError::IoError(e))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| LoaderError::IoError(e))?;
        
        let snapshot_file: SnapshotFile = bincode::deserialize(&buffer)
            .map_err(|e| LoaderError::Other(format!("Deserialization error: {}", e)))?;
        
        let cpu_context = Self::deserialize_context(emu, &snapshot_file.cpu_context_data)?;
        
        log::info!("📁 Loaded snapshot from {:?}", path);
        Ok((snapshot_file.snapshot, cpu_context))
    }
    
    // Helper functions
    fn read_memory_region(emu: &mut Unicorn<'static, ()>, base: u64, size: usize) -> Result<Vec<u8>, LoaderError> {
        let mut buffer = vec![0u8; size];
        emu.mem_read(base, &mut buffer)
            .map_err(|e| LoaderError::UnicornError(e))?;
        Ok(buffer)
    }
    
    fn write_memory_region(emu: &mut Unicorn<'static, ()>, base: u64, data: &[u8]) -> Result<(), LoaderError> {
        emu.mem_write(base, data)
            .map_err(|e| LoaderError::UnicornError(e))?;
        Ok(())
    }
    
    fn capture_pe_memory(emu: &mut Unicorn<'static, ()>) -> Result<HashMap<u64, Vec<u8>>, LoaderError> {
        let mut pe_memory = HashMap::new();
        
        // Get all loaded modules from MODULE_REGISTRY
        let modules = crate::pe::MODULE_REGISTRY.get_all_modules();
        
        for module in modules {
            let memory = Self::read_memory_region(emu, module.base_address, module.size as usize)?;
            pe_memory.insert(module.base_address, memory);
        }
        
        Ok(pe_memory)
    }
    
    fn capture_heap_state() -> HeapManagerState {
        let heap_manager = crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS.lock().unwrap();
        HeapManagerState {
            next_addr: heap_manager.next_addr(),
            allocations: heap_manager.get_allocations().clone(),
        }
    }
    
    fn capture_vfs_state() -> VfsState {
        let vfs = crate::emulation::vfs::VIRTUAL_FS.read().unwrap();
        let handles = vfs.get_all_handles()
            .into_iter()
            .map(|(k, v)| (k, FileHandleState {
                handle: v.handle,
                filename: v.filename.clone(),
                access_mode: v.access_mode,
                share_mode: v.share_mode,
                creation_flags: v.creation_flags,
                position: v.position,
            }))
            .collect();
        
        VfsState {
            handles,
            next_handle: vfs.next_handle(),
        }
    }
    
    fn capture_module_registry_state() -> ModuleRegistryState {
        let modules = crate::pe::MODULE_REGISTRY.get_all_modules();
        let mut module_map = HashMap::new();
        
        for module in modules {
            module_map.insert(module.name.clone(), ModuleState {
                name: module.name.clone(),
                base_address: module.base_address,
                size: module.size,
                exports: module.exports.clone(),
            });
        }
        
        let (next_dll_base, next_mock_addr) = crate::pe::MODULE_REGISTRY.get_allocation_info();
        
        ModuleRegistryState {
            modules: module_map,
            next_dll_base,
            next_mock_addr,
        }
    }
    
    fn restore_heap_state(state: &HeapManagerState) {
        let mut heap_manager = crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS.lock().unwrap();
        heap_manager.restore_state(state.next_addr, state.allocations.clone());
    }
    
    fn restore_vfs_state(state: &VfsState) {
        let mut vfs = crate::emulation::vfs::VIRTUAL_FS.write().unwrap();
        vfs.clear_handles();
        
        for (handle, file_state) in &state.handles {
            vfs.restore_handle(*handle, FileHandle {
                handle: file_state.handle,
                filename: file_state.filename.clone(),
                access_mode: file_state.access_mode,
                share_mode: file_state.share_mode,
                creation_flags: file_state.creation_flags,
                position: file_state.position,
            });
        }
        
        vfs.set_next_handle(state.next_handle);
    }
    
    fn restore_module_registry_state(state: &ModuleRegistryState) {
        crate::pe::MODULE_REGISTRY.restore_state(
            state.modules.iter().map(|(k, v)| {
                (k.clone(), LoadedModule::with_exports(
                    v.name.clone(),
                    v.base_address,
                    v.size,
                    v.exports.clone(),
                ))
            }).collect(),
            state.next_dll_base,
            state.next_mock_addr,
        );
    }
    
    fn serialize_context(context: &Context) -> Result<Vec<u8>, LoaderError> {
        // Unicorn contexts are opaque, so we need a workaround
        // We'll store essential register values that can be restored
        Ok(vec![]) // Placeholder - context is handled separately
    }
    
    fn deserialize_context(emu: &mut Unicorn<'static, ()>, _data: &[u8]) -> Result<Context, LoaderError> {
        // Create a new context for restoration
        emu.context_alloc()
            .map_err(|e| LoaderError::UnicornError(e))
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct SnapshotFile {
    snapshot: EmulatorSnapshot,
    cpu_context_data: Vec<u8>,
}

impl EmulatorSnapshot {
    pub fn get_name(&self) -> &str {
        &self.snapshot_name
    }
    
    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }
    
    pub fn get_instruction_count(&self) -> u64 {
        self.instruction_count
    }
}