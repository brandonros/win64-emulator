#[derive(Debug, Clone)]
pub struct ImportedFunction {
    dll_name: String,
    function_name: String,
    iat_address: u64,  // Address in the IAT where this function pointer is stored
}

#[derive(Debug)]
pub struct LoadedSection {
    name: String,
    virtual_address: u64,
    virtual_size: u64,
    raw_data: Vec<u8>,
}

impl LoadedSection {
    pub fn new(name: String, virtual_address: u64, virtual_size: u64, raw_data: Vec<u8>) -> Self {
        Self {
            name,
            virtual_address,
            virtual_size,
            raw_data,
        }
    }
    
    pub fn name(&self) -> &str {
        &self.name
    }
    
    pub fn virtual_address(&self) -> u64 {
        self.virtual_address
    }
    
    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }
    
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }
}

impl ImportedFunction {
    pub fn new(dll_name: String, function_name: String, iat_address: u64) -> Self {
        Self {
            dll_name,
            function_name,
            iat_address,
        }
    }
    
    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }
    
    pub fn function_name(&self) -> &str {
        &self.function_name
    }
    
    pub fn iat_address(&self) -> u64 {
        self.iat_address
    }
}

#[derive(Debug, Clone)]
pub struct IATEntry {
    pub iat_address: u64,           // Address in IAT where this entry lives
    pub resolved_address: u64,      // The mock function address we'll call
    pub import: ImportedFunction,
}
