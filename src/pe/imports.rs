use object::read::pe::PeFile64;

use crate::loader_error::LoaderError;
use super::types::ImportedFunction;

pub fn parse_imports(pe_file: &PeFile64, data: &[u8], image_base: u64) -> Result<Vec<ImportedFunction>, LoaderError> {
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
    let import_table_offset = rva_to_file_offset(pe_file, import_table_rva)
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
            if let Some(name_offset) = rva_to_file_offset(pe_file, name_rva) {
                read_cstring(data, name_offset as usize).unwrap_or_else(|_| format!("dll_{:x}", name_rva))
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
            let dll_imports = parse_dll_imports(
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
    
    let ilt_offset = rva_to_file_offset(pe_file, table_rva)
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
            if let Some(hint_name_offset) = rva_to_file_offset(pe_file, hint_name_rva) {
                // Skip hint (2 bytes) and read function name
                log::info!("        Hint/name file offset: 0x{:x}", hint_name_offset);
                read_cstring(data, hint_name_offset as usize + 2)
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