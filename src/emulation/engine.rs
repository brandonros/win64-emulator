use std::error::Error;
use std::fmt;
use std::rc::Rc;

#[derive(Debug)]
pub enum EmulatorError {
    RegisterRead,
    RegisterWrite,
    MemoryRead,
    MemoryWrite,
    InvalidMemory,
    NOMEM,
    Other(String),
}

impl fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmulatorError::RegisterRead => write!(f, "Failed to read register"),
            EmulatorError::RegisterWrite => write!(f, "Failed to write register"),
            EmulatorError::MemoryRead => write!(f, "Failed to read memory"),
            EmulatorError::MemoryWrite => write!(f, "Failed to write memory"),
            EmulatorError::InvalidMemory => write!(f, "Invalid memory access"),
            EmulatorError::NOMEM => write!(f, "Out of memory"),
            EmulatorError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for EmulatorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    Code,
    MemRead,
    MemWrite,
    MemReadAfter,
    MemInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemType {
    Read,
    Write,
    Fetch,
    ReadAfter,
    Invalid,
    ReadProt,
    WriteProt,
    FetchProt,
}

pub type HookHandle = usize;

pub type CodeHookCallback = Rc<dyn Fn(&mut dyn EmulatorEngine, u64, u32)>;
pub type MemHookCallback = Rc<dyn Fn(&mut dyn EmulatorEngine, MemType, u64, usize, i64) -> bool>;

#[derive(Debug, Clone, Copy)]
pub enum X86Register {
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RBP,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RIP,
    RFLAGS,
    CS,
    DS,
    ES,
    FS,
    GS,
    SS,
}

pub trait EmulatorEngine {
    fn reg_read(&mut self, reg: X86Register) -> Result<u64, EmulatorError>;
    
    fn reg_write(&mut self, reg: X86Register, value: u64) -> Result<(), EmulatorError>;
    
    fn mem_read(&mut self, address: u64, buf: &mut [u8]) -> Result<(), EmulatorError>;

    fn mem_read_as_vec(&mut self, address: u64, size: usize) -> Result<Vec<u8>, EmulatorError> {
        let mut buf = vec![0u8; size];
        self.mem_read(address, &mut buf)?;
        Ok(buf)
    }
    
    fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), EmulatorError>;
    
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), EmulatorError>;
    
    fn mem_unmap(&mut self, address: u64, size: usize) -> Result<(), EmulatorError>;
    
    fn mem_protect(&mut self, address: u64, size: usize, perms: u32) -> Result<(), EmulatorError>;
    
    fn mem_regions(&mut self) -> Result<Vec<(u64, u64)>, EmulatorError>;
    
    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<(), EmulatorError>;
    
    fn emu_stop(&mut self) -> Result<(), EmulatorError>;
    
    // Hook management
    fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: CodeHookCallback,
    ) -> Result<HookHandle, EmulatorError>;
    
    fn add_mem_hook(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: MemHookCallback,
    ) -> Result<HookHandle, EmulatorError>;
    
    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError>;
    
    // Get underlying Unicorn instance if this backend uses one
    // This is a hack to support the existing hook callbacks
    fn as_unicorn(&mut self) -> Option<&mut unicorn_engine::Unicorn<'static, ()>> {
        None
    }
}