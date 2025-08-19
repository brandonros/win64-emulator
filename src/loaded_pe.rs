use std::collections::HashMap;

use object::{read::pe::PeFile64, Architecture, BinaryFormat, Object as _, ObjectSection as _, ObjectSymbol as _};
use unicorn_engine::Permission;

use crate::{loader_error::LoaderError, structs::{ImportedFunction, LoadedSection}};

#[derive(Debug, Clone)]
pub struct IATEntry {
    pub iat_address: u64,           // Address in IAT where this entry lives
    pub resolved_address: u64,      // The mock function address we'll call
    pub import: ImportedFunction,
}

#[derive(Debug)]
pub struct LoadedPE {
    entry_point: u64,
    image_base: u64,
    sections: Vec<LoadedSection>,
    symbols: HashMap<String, u64>,
    imports: Vec<ImportedFunction>,
    iat_entries: Vec<IATEntry>,    // Pre-resolved IAT entries
}

impl LoadedPE {
    pub fn from_file(path: &str) -> Result<Self, LoaderError> {
        // Read the PE file
        let data = std::fs::read(path)?;
        let obj_file = object::File::parse(&*data)?;
        
        // Verify it's a PE64 file
        if obj_file.format() != BinaryFormat::Pe {
            return Err(LoaderError::from("Not a PE file"));
        }
        
        if obj_file.architecture() != Architecture::X86_64 {
            return Err(LoaderError::from("Not a 64-bit executable"));
        }
        
        // Get PE-specific information
        let pe_file = PeFile64::parse(&*data)?;
        let image_base = pe_file.nt_headers().optional_header.image_base.get(object::LittleEndian);
        let entry_point = image_base + pe_file.nt_headers().optional_header.address_of_entry_point.get(object::LittleEndian) as u64;
        
        log::info!("📋 PE64 File Information:");
        log::info!("  Image Base: 0x{:016x}", image_base);
        log::info!("  Entry Point: 0x{:016x}", entry_point);
        
        // Load sections - handle both object crate addresses and PE RVAs
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
                permissions,
            ));
        }
        
        // Load symbols (if available)
        let mut symbols = HashMap::new();
        for symbol in obj_file.symbols() {
            if let (Ok(name), address) = (symbol.name(), symbol.address()) {
                symbols.insert(name.to_string(), image_base + address);
            }
        }
        
        // Parse imports from PE import table
        let imports = Self::parse_imports(&pe_file, &data, image_base)?;
        
        // Build IAT entries with resolved mock addresses
        let mut iat_entries = Vec::new();
        let mock_function_base = 0x7F000000u64;
        let mut current_mock_addr = mock_function_base;
        
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
        log::info!("  Created {} IAT entries", iat_entries.len());
        
        Ok(LoadedPE {
            entry_point,
            image_base,
            sections,
            symbols,
            imports,
            iat_entries,
        })
    }
    
    fn parse_imports(pe_file: &PeFile64, data: &[u8], image_base: u64) -> Result<Vec<ImportedFunction>, LoaderError> {
        use object::LittleEndian;
        use object::pe::*;
        
        let mut imports = Vec::new();
        
        // Get import directory from data directories
        let data_dirs = pe_file.data_directories();
        let import_dir = match data_dirs.get(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(dir) => dir,
            None => {
                log::info!("  No import directory found");
                return Ok(imports);
            }
        };
        
        let import_table_rva = import_dir.virtual_address.get(LittleEndian);
        if import_table_rva == 0 {
            log::info!("  Import table is empty");
            return Ok(imports);
        }
        
        log::info!("🔗 Parsing imports from RVA 0x{:x}", import_table_rva);
        
        // Convert RVA to file offset
        let import_table_offset = Self::rva_to_file_offset(pe_file, import_table_rva)
            .ok_or("Could not convert import table RVA to file offset")?;
        
        let mut offset = import_table_offset as usize;
        
        // Parse import descriptors (20 bytes each)
        loop {
            if offset + 20 > data.len() {
                break;
            }
            
            let import_lookup_table = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            let name_rva = u32::from_le_bytes([
                data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]
            ]);
            let import_address_table = u32::from_le_bytes([
                data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19]
            ]);
            
            // End of import table
            if import_lookup_table == 0 && name_rva == 0 && import_address_table == 0 {
                break;
            }
            
            // Get DLL name
            let dll_name = if name_rva != 0 {
                if let Some(name_offset) = Self::rva_to_file_offset(pe_file, name_rva) {
                    Self::read_cstring(data, name_offset as usize).unwrap_or_else(|_| format!("dll_{:x}", name_rva))
                } else {
                    format!("unknown_dll_{:x}", name_rva)
                }
            } else {
                "unknown_dll".to_string()
            };
            
            log::info!("  📚 DLL: {} (ILT: 0x{:x}, IAT: 0x{:x})", dll_name, import_lookup_table, import_address_table);
            
            // Parse functions from this DLL
            if import_lookup_table != 0 || import_address_table != 0 {
                log::info!("    ILT: 0x{:x}, IAT: 0x{:x}", import_lookup_table, import_address_table);
                let dll_imports = Self::parse_dll_imports(
                    pe_file, 
                    data,
                    &dll_name, 
                    import_lookup_table, 
                    import_address_table, 
                    image_base
                ).unwrap_or_else(|e| {
                    log::info!("    ⚠️ Failed to parse imports: {}", e);
                    Vec::new()
                });
                
                log::info!("    Found {} functions", dll_imports.len());
                imports.extend(dll_imports);
            }
            
            offset += 20;
        }
        
        Ok(imports)
    }
    
    fn parse_dll_imports(
        pe_file: &PeFile64,
        data: &[u8],
        dll_name: &str,
        import_lookup_table_rva: u32,
        import_address_table_rva: u32,
        image_base: u64,
    ) -> Result<Vec<ImportedFunction>, LoaderError> {
        let mut imports = Vec::new();
        
        // Use IAT if ILT is not available (some packers/protectors do this)
        let table_rva = if import_lookup_table_rva != 0 {
            import_lookup_table_rva
        } else {
            import_address_table_rva
        };
        
        let ilt_offset = Self::rva_to_file_offset(pe_file, table_rva)
            .ok_or("Could not convert table RVA to file offset")?;
        
        log::info!("      Table RVA 0x{:x} -> file offset 0x{:x}", table_rva, ilt_offset);
        
        let mut ilt_pos = ilt_offset as usize;
        let mut iat_entry_index = 0;
        
        // Parse Import Lookup Table (64-bit entries for PE64)
        loop {
            if ilt_pos + 8 > data.len() {
                log::info!("      End of data reached at offset 0x{:x}", ilt_pos);
                break;
            }
            
            let ilt_entry = u64::from_le_bytes([
                data[ilt_pos], data[ilt_pos + 1], data[ilt_pos + 2], data[ilt_pos + 3],
                data[ilt_pos + 4], data[ilt_pos + 5], data[ilt_pos + 6], data[ilt_pos + 7],
            ]);
            
            if ilt_entry == 0 {
                log::info!("      End of ILT (null entry) at offset 0x{:x}", ilt_pos);
                break;
            }
            
            log::info!("      ILT entry[{}]: 0x{:016x}", iat_entry_index, ilt_entry);
            
            let function_name = if ilt_entry & 0x8000000000000000 != 0 {
                // Import by ordinal
                let ordinal = ilt_entry & 0xFFFF;
                log::info!("        Import by ordinal: {}", ordinal);
                format!("Ordinal_{}", ordinal)
            } else {
                // Import by name
                let hint_name_rva = (ilt_entry & 0x7FFFFFFF) as u32;
                log::info!("        Import by name, hint/name RVA: 0x{:x}", hint_name_rva);
                if let Some(hint_name_offset) = Self::rva_to_file_offset(pe_file, hint_name_rva) {
                    // Skip hint (2 bytes) and read function name
                    log::info!("        Hint/name file offset: 0x{:x}", hint_name_offset);
                    Self::read_cstring(data, hint_name_offset as usize + 2)
                        .unwrap_or_else(|_| format!("func_{:x}", hint_name_rva))
                } else {
                    format!("unknown_func_{:x}", hint_name_rva)
                }
            };
            
            // Calculate IAT address for this import
            let iat_address = image_base + import_address_table_rva as u64 + (iat_entry_index * 8) as u64;
            
            log::info!("        Function: {} at IAT 0x{:016x}", function_name, iat_address);
            
            imports.push(ImportedFunction::new(
                dll_name.to_string(),
                function_name,
                iat_address,
            ));
            
            ilt_pos += 8;
            iat_entry_index += 1;
            
            // Safety limit to avoid infinite loops
            if iat_entry_index > 1000 {
                log::info!("      Hit safety limit of 1000 imports");
                break;
            }
        }
        
        Ok(imports)
    }
    
    fn rva_to_file_offset(pe_file: &PeFile64, rva: u32) -> Option<u32> {
        let sections = pe_file.section_table();
        
        for section in sections.iter() {
            let section_va = section.virtual_address.get(object::LittleEndian);
            let section_size = section.virtual_size.get(object::LittleEndian);
            let raw_ptr = section.pointer_to_raw_data.get(object::LittleEndian);
            
            if rva >= section_va && rva < section_va + section_size {
                return Some(rva - section_va + raw_ptr);
            }
        }
        
        None
    }
    
    fn read_cstring(data: &[u8], mut offset: usize) -> Result<String, LoaderError> {
        let mut bytes = Vec::new();
        while offset < data.len() && data[offset] != 0 {
            bytes.push(data[offset]);
            offset += 1;
        }
        String::from_utf8(bytes).map_err(|_| LoaderError::from("Invalid UTF-8 in string"))
    }
    
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }
    
    pub fn image_base(&self) -> u64 {
        self.image_base
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
}
