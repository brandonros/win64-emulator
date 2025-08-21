use object::read::pe::PeFile64;
use std::collections::HashMap;
use crate::{loader_error::LoaderError, pe::utils};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ExportedFunction {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}

// Parse exports from a PE file
pub fn parse_exports(pe_file: &PeFile64, data: &[u8], base_address: u64) -> Result<Vec<ExportedFunction>, LoaderError> {
    use object::LittleEndian;
    use object::pe::*;
    
    let mut exports = Vec::new();
    
    let data_dirs = pe_file.data_directories();
    let export_dir = match data_dirs.get(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(dir) => dir,
        None => {
            log::info!("  No export directory found");
            return Ok(exports);
        }
    };
    
    let export_table_rva = export_dir.virtual_address.get(LittleEndian);
    if export_table_rva == 0 {
        log::info!("  Export table is empty");
        return Ok(exports);
    }
    
    log::info!("📦 Parsing exports from RVA 0x{:x}", export_table_rva);
    
    let export_table_offset = utils::rva_to_file_offset(pe_file, export_table_rva)
        .ok_or("Could not convert export table RVA to file offset")?;
    
    let offset = export_table_offset as usize;
    
    // Ensure we have enough data for the export directory structure
    if offset + 40 > data.len() {
        return Err(LoaderError::from("Export directory extends beyond file"));
    }
    
    // Parse export directory structure
    let _characteristics = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
    ]);
    let _time_date_stamp = u32::from_le_bytes([
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
    ]);
    let _major_version = u16::from_le_bytes([
        data[offset + 8], data[offset + 9]
    ]);
    let _minor_version = u16::from_le_bytes([
        data[offset + 10], data[offset + 11]
    ]);
    let _name_rva = u32::from_le_bytes([
        data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]
    ]);
    let ordinal_base = u32::from_le_bytes([
        data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19]
    ]);
    let num_functions = u32::from_le_bytes([
        data[offset + 20], data[offset + 21], data[offset + 22], data[offset + 23]
    ]);
    let num_names = u32::from_le_bytes([
        data[offset + 24], data[offset + 25], data[offset + 26], data[offset + 27]
    ]);
    let addr_table_rva = u32::from_le_bytes([
        data[offset + 28], data[offset + 29], data[offset + 30], data[offset + 31]
    ]);
    let name_table_rva = u32::from_le_bytes([
        data[offset + 32], data[offset + 33], data[offset + 34], data[offset + 35]
    ]);
    let ordinal_table_rva = u32::from_le_bytes([
        data[offset + 36], data[offset + 37], data[offset + 38], data[offset + 39]
    ]);
    
    log::info!("  Export directory: {} functions, {} names", num_functions, num_names);
    
    // Get table offsets
    let addr_table_offset = utils::rva_to_file_offset(pe_file, addr_table_rva)
        .ok_or("Could not convert address table RVA")? as usize;
    let name_table_offset = if num_names > 0 {
        utils::rva_to_file_offset(pe_file, name_table_rva)
            .ok_or("Could not convert name table RVA")? as usize
    } else {
        0
    };
    let ordinal_table_offset = if num_names > 0 {
        utils::rva_to_file_offset(pe_file, ordinal_table_rva)
            .ok_or("Could not convert ordinal table RVA")? as usize
    } else {
        0
    };
    
    // Create a map of ordinal to name for named exports
    let mut ordinal_to_name: HashMap<u16, String> = HashMap::new();
    
    // Parse named exports
    for i in 0..num_names as usize {
        let name_rva_offset = name_table_offset + (i * 4);
        if name_rva_offset + 4 > data.len() {
            break;
        }
        
        let name_rva = u32::from_le_bytes([
            data[name_rva_offset], data[name_rva_offset + 1], 
            data[name_rva_offset + 2], data[name_rva_offset + 3]
        ]);
        
        let ordinal_offset = ordinal_table_offset + (i * 2);
        if ordinal_offset + 2 > data.len() {
            break;
        }
        
        let ordinal = u16::from_le_bytes([
            data[ordinal_offset], data[ordinal_offset + 1]
        ]);
        
        if let Some(name_offset) = utils::rva_to_file_offset(pe_file, name_rva) {
            if let Ok(func_name) = utils::read_cstring(data, name_offset as usize) {
                ordinal_to_name.insert(ordinal, func_name);
            }
        }
    }
    
    // Parse all exports (both named and ordinal-only)
    for ordinal_index in 0..num_functions as usize {
        let addr_offset = addr_table_offset + (ordinal_index * 4);
        if addr_offset + 4 > data.len() {
            break;
        }
        
        let func_rva = u32::from_le_bytes([
            data[addr_offset], data[addr_offset + 1], 
            data[addr_offset + 2], data[addr_offset + 3]
        ]);
        
        // Skip null entries
        if func_rva == 0 {
            continue;
        }
        
        let ordinal = (ordinal_base + ordinal_index as u32) as u16;
        
        // Check if this is a forwarder RVA (points within the export directory)
        let _is_forwarder = func_rva >= export_table_rva && 
                          func_rva < (export_table_rva + export_dir.size.get(LittleEndian));
        
        // TODO: handle forwards differently
        
        // Get the name if it exists, otherwise use ordinal
        let name = ordinal_to_name.get(&(ordinal_index as u16))
            .cloned()
            .unwrap_or_else(|| format!("Ordinal_{}", ordinal));
        
        exports.push(ExportedFunction {
            name,
            address: base_address + func_rva as u64,
            ordinal,
        });
    }
    
    log::info!("  Found {} exports", exports.len());
    
    Ok(exports)
}
