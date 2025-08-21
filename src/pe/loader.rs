use std::collections::HashMap;

use object::pe::{ImageDosHeader, ImageNtHeaders64};
use object::LittleEndian;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use object::read::pe::ImageNtHeaders as _;
use unicorn_engine::Permission;

use crate::loader_error::LoaderError;
use super::types::{ImportedFunction, LoadedSection, IATEntry};
use super::imports;
use super::exports::{self, ExportedFunction};

// TODO: This should be moved to emulation module
const MOCK_FUNCTION_BASE: u64 = 0x7F000000;

#[derive(Debug)]
pub struct LoadedPE {
    entry_point: u64,
    image_base: u64,
    image_size: usize,
    sections: Vec<LoadedSection>,
    symbols: HashMap<String, u64>,
    imports: Vec<ImportedFunction>,
    iat_entries: Vec<IATEntry>,    // Pre-resolved IAT entries
    exports: HashMap<String, ExportedFunction>, // Exported functions indexed by name
}

impl LoadedPE {
    pub fn from_file(path: &str) -> Result<Self, LoaderError> {
        let file_bytes = std::fs::read(path)?;
        let file_kind = object::FileKind::parse(&*file_bytes)?;
        assert_eq!(file_kind, object::FileKind::Pe64);
        let dos_header = ImageDosHeader::parse(&*file_bytes)?;
        let mut offset: u64 = dos_header.nt_headers_offset().into();
        let (nt_headers, _data_directories) = ImageNtHeaders64::parse(&*file_bytes, &mut offset)?;
        let optional_header = nt_headers.optional_header();
        let image_base = optional_header.image_base.get(LittleEndian);
        let entry_point_rva = optional_header.address_of_entry_point.get(LittleEndian) as u64;
        let entry_point = image_base + entry_point_rva;
        let image_size = optional_header.size_of_image.get(LittleEndian) as usize;
        
        log::info!("📋 PE64 File Information:");
        log::info!("  Image Base: 0x{:016x}", image_base);
        log::info!("  Entry Point: 0x{:016x}", entry_point);
        log::info!("  Image Size: 0x{:x}", image_size);
        
        // Load sections - handle both object crate addresses and PE RVAs
        let obj_file = object::File::parse(&*file_bytes)?;
        let mut sections = Vec::new();
        for section in obj_file.sections() {
            let name = section.name().unwrap_or("<unknown>").to_string();
            let section_addr = section.address();
            
            // Check if this looks like a PE RVA (relative virtual address) or absolute address
            let virtual_address = if section_addr < 0x100000 {
                // Looks like an RVA, add to image base
                image_base + section_addr
            } else {
                // Looks like an absolute address, use as-is but warn if it doesn't match image base
                if section_addr < image_base || section_addr > image_base + 0x10000000 {
                    log::info!("  ⚠️  Section '{}' has suspicious VA: 0x{:016x} (image base: 0x{:016x})", 
                             name, section_addr, image_base);
                }
                section_addr
            };
            
            let virtual_size = section.size();
            let raw_data = section.data()?.to_vec();
            
            // Determine permissions based on section characteristics
            let permissions = Self::get_section_permissions(&section);
            
            log::info!("  Section '{}': VA=0x{:016x} (raw: 0x{:016x}), Size=0x{:x}, Perms={:?}", 
                     name, virtual_address, section_addr, virtual_size, permissions);
            
            sections.push(LoadedSection::new(
                name,
                virtual_address,
                virtual_size,
                raw_data,
            ));
        }
        
        // Load symbols (if available)
        let mut symbols = HashMap::new();
        for symbol in obj_file.symbols() {
            if let (Ok(name), address) = (symbol.name(), symbol.address()) {
                symbols.insert(name.to_string(), image_base + address);
            }
        }

        // open a pe64?
        let pe_file = object::read::pe::PeFile64::parse(&*file_bytes)?;
        
        // Parse imports from PE import table
        let imports = imports::parse_imports(&pe_file, &file_bytes, image_base)?;
        
        // Parse exports from PE export table
        let export_list = exports::parse_exports(&pe_file, &file_bytes, image_base)?;
        let mut exports = HashMap::new();
        for export in export_list {
            exports.insert(export.name.clone(), export);
        }
        
        // Build IAT entries with resolved mock addresses
        let mut iat_entries = Vec::new();
        let mut current_mock_addr = MOCK_FUNCTION_BASE;
        
        for import in &imports {
            iat_entries.push(IATEntry {
                iat_address: import.iat_address(),
                resolved_address: current_mock_addr,
                import: import.clone(),
            });
            current_mock_addr += 0x10; // Space between mock functions
        }
        
        log::info!("  Loaded {} symbols", symbols.len());
        log::info!("  Found {} imported functions", imports.len());
        log::info!("  Found {} exported functions", exports.len());
        log::info!("  Created {} IAT entries", iat_entries.len());
        
        Ok(LoadedPE {
            entry_point,
            image_base,
            image_size,
            sections,
            symbols,
            imports,
            iat_entries,
            exports,
        })
    }
    
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }
    
    pub fn image_base(&self) -> u64 {
        self.image_base
    }
    
    pub fn image_size(&self) -> usize {
        self.image_size
    }
    
    pub fn sections(&self) -> &[LoadedSection] {
        &self.sections
    }
    
    pub fn symbols(&self) -> &HashMap<String, u64> {
        &self.symbols
    }
    
    pub fn imports(&self) -> &[ImportedFunction] {
        &self.imports
    }
    
    pub fn iat_entries(&self) -> &[IATEntry] {
        &self.iat_entries
    }
    
    pub fn exports(&self) -> &HashMap<String, ExportedFunction> {
        &self.exports
    }
    
    fn get_section_permissions(section: &object::Section) -> Permission {
        let mut perms = Permission::empty();
        
        // Always readable by default
        perms |= Permission::READ;
        
        // Check section flags (this is simplified - real PE loading is more complex)
        let name = section.name().unwrap_or("");
        
        match name {
            ".text" | ".code" => perms | Permission::EXEC,
            ".data" | ".bss" | ".rdata" => perms | Permission::WRITE,
            _ => {
                // Try to infer from section characteristics if available
                // For simplicity, assume data sections are writable
                if name.contains("data") || name.contains("bss") {
                    perms | Permission::WRITE
                } else {
                    perms
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kernel32_imports() {
        // Load the test PE file
        let pe_path = "./assets/enigma_test_protected.exe";
        let loaded_pe = LoadedPE::from_file(pe_path).expect("Failed to load PE file");
        
        // Expected kernel32.dll functions based on the image shown
        let expected_kernel32_functions = vec![
            "GetModuleHandleA",
            "GetProcAddress",
            "ExitProcess",
            "LoadLibraryA"
        ];
        
        // Filter imports for kernel32.dll
        let kernel32_imports: Vec<_> = loaded_pe.imports()
            .iter()
            .filter(|imp| imp.dll_name().to_lowercase() == "kernel32.dll")
            .collect();
        
        // Verify we have kernel32 imports
        assert!(!kernel32_imports.is_empty(), "No kernel32.dll imports found");
        
        // Check each expected function is present
        for expected_func in &expected_kernel32_functions {
            let found = kernel32_imports
                .iter()
                .any(|imp| imp.function_name() == *expected_func);
            
            assert!(found, "Missing kernel32.dll function: {}", expected_func);
        }
        
        // Verify the count matches
        assert_eq!(kernel32_imports.len(), 4, 
            "Expected 4 kernel32.dll imports, found {}", kernel32_imports.len());
        
        // Verify IAT addresses are set (non-zero)
        for import in &kernel32_imports {
            assert_ne!(import.iat_address(), 0, 
                "IAT address for {} should not be 0", import.function_name());
        }
    }
    
    #[test]
    fn test_kernel32_exports() {
        // Load kernel32.dll from the Windows system directory
        let kernel32_path = "./assets/kernel32.dll";
        
        let loaded_pe = LoadedPE::from_file(kernel32_path).expect("Failed to load kernel32.dll");
        
        // Get all exports
        let exports = loaded_pe.exports();
        
        // Verify we have exports
        assert!(!exports.is_empty(), "kernel32.dll should have exports");
        
        // Check for GetModuleHandleA specifically
        let get_module_handle_a = exports.get("GetModuleHandleA");
        
        assert!(get_module_handle_a.is_some(), "GetModuleHandleA should be exported by kernel32.dll");
        
        let export = get_module_handle_a.unwrap();
        assert_ne!(export.address, 0, "GetModuleHandleA should have a valid address");
        assert_ne!(export.ordinal, 0, "GetModuleHandleA should have a valid ordinal");
        
        // Check for a few other common exports
        let common_exports = vec![
            "GetModuleHandleW",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "ExitProcess",
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle"
        ];
        
        for export_name in &common_exports {
            assert!(exports.contains_key(*export_name), "{} should be exported by kernel32.dll", export_name);
        }
        
        log::info!("kernel32.dll has {} total exports", exports.len());
        log::info!("GetModuleHandleA found at address: 0x{:x}, ordinal: {}", 
                 export.address, export.ordinal);
    }

    #[test] 
    fn test_pe_parsing_steps() {
        let path = "/Users/brandon/Desktop/win64-emulator/assets/enigma_test_protected.exe"; // Replace with actual test file
        let file_bytes = std::fs::read(path).expect("Failed to read file");
        
        // Step 2: Parse file kind  
        let file_kind = object::FileKind::parse(&*file_bytes).expect("Failed to get file kind");
        assert_eq!(file_kind, object::FileKind::Pe64);
        
        // Step 3: Parse DOS header
        let dos_header = ImageDosHeader::parse(&*file_bytes).expect("Failed to parse DOS header");
        
        // Step 4: Parse NT headers
        let mut offset: u64 = dos_header.nt_headers_offset().into();
        let (nt_headers, _data_directories) = ImageNtHeaders64::parse(&*file_bytes, &mut offset)
            .expect("Failed to parse NT headers");
        
        // Step 5: Extract and verify PE information
        let optional_header = nt_headers.optional_header();
        let image_base = optional_header.image_base.get(LittleEndian);
        let entry_point_rva = optional_header.address_of_entry_point.get(LittleEndian) as u64;
        let image_size = optional_header.size_of_image.get(LittleEndian) as usize;
        
        let expected_image_base = 0x0000000140000000; // Common for 64-bit executables
        let expected_entry_point_rva = 0x0000000001058b8c; // Replace with actual expected value
        let expected_entry_point = expected_image_base + expected_entry_point_rva;
        let expected_image_size = 0x105d000; // Replace with actual expected value

        assert_eq!(image_base, expected_image_base, "Image base mismatch!");
        assert_eq!(entry_point_rva, expected_entry_point_rva, "Entry point mismatch!");
        assert_eq!(image_size, expected_image_size, "Image size mismatch!");

        let loaded_pe = LoadedPE::from_file(path).expect("Failed to load PE with from_file");
        assert_eq!(loaded_pe.entry_point, expected_entry_point);
    }
}
