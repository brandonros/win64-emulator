use object::read::pe::PeFile64;

use crate::loader_error::LoaderError;

pub fn rva_to_file_offset(pe_file: &PeFile64, rva: u32) -> Option<u32> {
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

pub fn read_cstring(data: &[u8], mut offset: usize) -> Result<String, LoaderError> {
    let mut bytes = Vec::new();
    while offset < data.len() && data[offset] != 0 {
        bytes.push(data[offset]);
        offset += 1;
    }
    String::from_utf8(bytes).map_err(|_| LoaderError::from("Invalid UTF-8 in string"))
}
