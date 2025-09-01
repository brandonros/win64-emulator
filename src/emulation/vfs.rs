use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::path::PathBuf;

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    
    fn normalize_windows_path(&self, filename: &str) -> PathBuf {
        let mut normalized_filename = if filename.starts_with("\\??\\") {
            filename[4..].to_string()
        } else if filename.starts_with("\\") {
            filename[1..].to_string()
        } else {
            filename.to_string()
        };
        
        // Replace C: with /c (and other drive letters)
        if normalized_filename.len() >= 2 && normalized_filename.chars().nth(1) == Some(':') {
            let drive_letter = normalized_filename.chars().nth(0).unwrap().to_lowercase().to_string();
            normalized_filename = format!("/{}{}", drive_letter, &normalized_filename[2..]);
        }
        
        // Replace backslashes with forward slashes
        normalized_filename = normalized_filename.replace("\\", "/");
        
        // Remove leading slash if present to make it a relative path
        if normalized_filename.starts_with("/") {
            normalized_filename = normalized_filename[1..].to_string();
        }
        
        self.mock_files_path.join(&normalized_filename)
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
    
    pub fn file_exists(&self, filename: &str) -> bool {
        let file_path = self.normalize_windows_path(filename);
        file_path.exists()
    }
    
    pub fn get_file_info(&self, handle: u64) -> Option<&FileHandle> {
        self.handles.get(&handle)
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
        let file_path = self.normalize_windows_path(filename);
        
        if file_path.exists() {
            log::info!("[VFS] Reading mock file from: {:?}", file_path);
            std::fs::read(file_path)
        } else {
            panic!("[VFS] Mock file not found: {:?}, will use default mock data", file_path);
            //Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Mock file not found"))
        }
    }
    
    pub fn update_position(&mut self, handle: u64, new_position: u64) {
        if let Some(file_handle) = self.handles.get_mut(&handle) {
            file_handle.position = new_position;
        }
    }
    
    pub fn find_files(&self, pattern: &str) -> Vec<String> {
        // Convert Windows pattern to a path for searching
        let normalized_pattern = if pattern.starts_with("\\??\\") {
            &pattern[4..]
        } else {
            pattern
        };
        
        // Split into directory and file pattern
        let (dir_path, file_pattern) = if let Some(pos) = normalized_pattern.rfind('\\') {
            (&normalized_pattern[..pos], &normalized_pattern[pos + 1..])
        } else {
            (".", normalized_pattern)
        };
        
        let search_dir = self.normalize_windows_path(dir_path);
        
        log::info!("[VFS] Searching for files matching '{}' in {:?}", file_pattern, search_dir);
        
        let mut results = Vec::new();
        
        // If the directory doesn't exist, return empty results
        if !search_dir.exists() {
            log::info!("[VFS] Directory {:?} does not exist", search_dir);
            return results;
        }
        
        // Convert wildcard pattern to regex (kept for potential future use)
        let _regex_pattern = file_pattern
            .replace(".", "\\.")
            .replace("*", ".*")
            .replace("?", ".");
        
        // Try to list files in the directory
        if let Ok(entries) = std::fs::read_dir(&search_dir) {
            for entry in entries.flatten() {
                if let Some(file_name) = entry.file_name().to_str() {
                    // Simple pattern matching (could use regex crate for more accuracy)
                    if Self::matches_pattern(file_name, file_pattern) {
                        results.push(file_name.to_string());
                        log::info!("[VFS] Found matching file: {}", file_name);
                    }
                }
            }
        }
        
        results
    }
    
    fn matches_pattern(name: &str, pattern: &str) -> bool {
        // Simple wildcard matching
        if pattern == "*" || pattern == "*.*" {
            return true;
        }
        
        let mut name_chars = name.chars().peekable();
        let mut pattern_chars = pattern.chars().peekable();
        
        while pattern_chars.peek().is_some() {
            match pattern_chars.next() {
                Some('*') => {
                    // Match zero or more characters
                    if pattern_chars.peek().is_none() {
                        return true; // * at end matches everything
                    }
                    // Find next non-wildcard character in pattern
                    let next_pattern_char = pattern_chars.peek().copied();
                    if let Some(next_char) = next_pattern_char {
                        if next_char == '*' || next_char == '?' {
                            continue; // Handle multiple wildcards
                        }
                        // Find this character in the name
                        while let Some(name_char) = name_chars.peek() {
                            if *name_char == next_char {
                                break;
                            }
                            name_chars.next();
                        }
                    }
                }
                Some('?') => {
                    // Match exactly one character
                    if name_chars.next().is_none() {
                        return false;
                    }
                }
                Some(pattern_char) => {
                    // Match exact character
                    if name_chars.next() != Some(pattern_char) {
                        return false;
                    }
                }
                None => break,
            }
        }
        
        // Check if we've consumed all of the name
        pattern_chars.peek().is_none() && name_chars.peek().is_none()
    }
}

pub static VIRTUAL_FS: LazyLock<RwLock<VirtualFileSystem>> = LazyLock::new(|| {
    RwLock::new(VirtualFileSystem::new())
});