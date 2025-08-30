use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FileHandle {
    pub handle: u64,
    pub filename: String,
    pub access_mode: u32,
    pub share_mode: u32,
    pub creation_flags: u32,
    pub position: u64,
}

impl FileHandle {
    pub fn new(handle: u64, filename: String, access_mode: u32, share_mode: u32, creation_flags: u32) -> Self {
        Self {
            handle,
            filename,
            access_mode,
            share_mode,
            creation_flags,
            position: 0,
        }
    }
}

pub struct VirtualFileSystem {
    handles: HashMap<u64, FileHandle>,
    next_handle: u64,
    mock_files_path: PathBuf,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle: 0x1000,
            mock_files_path: PathBuf::from("mock_files"),
        }
    }
    
    pub fn create_handle(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 0x10;
        handle
    }
    
    pub fn register_file(&mut self, filename: String, access_mode: u32, share_mode: u32, creation_flags: u32) -> u64 {
        let handle = self.create_handle();
        let file_handle = FileHandle::new(handle, filename.clone(), access_mode, share_mode, creation_flags);
        self.handles.insert(handle, file_handle);
        log::debug!("[VFS] Registered handle 0x{:x} for file '{}'", handle, filename);
        handle
    }
    
    pub fn get_file_info(&self, handle: u64) -> Option<&FileHandle> {
        self.handles.get(&handle)
    }
    
    pub fn get_file_info_mut(&mut self, handle: u64) -> Option<&mut FileHandle> {
        self.handles.get_mut(&handle)
    }
    
    pub fn get_filename(&self, handle: u64) -> Option<String> {
        self.handles.get(&handle).map(|fh| fh.filename.clone())
    }
    
    pub fn close_handle(&mut self, handle: u64) -> bool {
        if let Some(file_handle) = self.handles.remove(&handle) {
            log::debug!("[VFS] Closed handle 0x{:x} for file '{}'", handle, file_handle.filename);
            true
        } else {
            log::warn!("[VFS] Attempted to close non-existent handle 0x{:x}", handle);
            false
        }
    }
    
    pub fn read_mock_file(&self, filename: &str) -> Result<Vec<u8>, std::io::Error> {
        let normalized_filename = if filename.starts_with("\\??\\") {
            &filename[4..]
        } else if filename.starts_with("\\") {
            &filename[1..]
        } else {
            filename
        };
        
        let file_path = self.mock_files_path.join(normalized_filename);
        
        if file_path.exists() {
            log::info!("[VFS] Reading mock file from: {:?}", file_path);
            std::fs::read(file_path)
        } else {
            log::debug!("[VFS] Mock file not found: {:?}, will use default mock data", file_path);
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Mock file not found"))
        }
    }
    
    pub fn update_position(&mut self, handle: u64, new_position: u64) {
        if let Some(file_handle) = self.handles.get_mut(&handle) {
            file_handle.position = new_position;
        }
    }
    
    pub fn is_valid_handle(&self, handle: u64) -> bool {
        self.handles.contains_key(&handle)
    }
}

pub static VIRTUAL_FS: LazyLock<RwLock<VirtualFileSystem>> = LazyLock::new(|| {
    RwLock::new(VirtualFileSystem::new())
});