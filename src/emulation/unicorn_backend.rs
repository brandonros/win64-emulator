use unicorn_engine::{Unicorn, RegisterX86, Arch, Mode};
use super::engine::{EmulatorEngine, EmulatorError, X86Register, HookType, HookHandle, CodeHookCallback, MemHookCallback};

/// UnicornEngine wraps a Unicorn emulator to implement the EmulatorEngine trait
pub struct UnicornEngine {
    emu: Unicorn<'static, ()>,
}

impl UnicornEngine {
    pub fn new() -> Result<Self, EmulatorError> {
        let emu = Unicorn::new(Arch::X86, Mode::MODE_64)
            .map_err(|e| EmulatorError::Other(format!("Failed to create Unicorn: {:?}", e)))?;
        Ok(Self { emu })
    }
    
    pub fn from_unicorn(emu: Unicorn<'static, ()>) -> Self {
        Self { emu }
    }
    
    /// Create a temporary wrapper around a Unicorn reference for use in hooks
    /// This creates a wrapper that borrows the Unicorn - the wrapper MUST NOT outlive the reference
    pub fn from_unicorn_ref<'a>(emu: &'a mut Unicorn<'static, ()>) -> &'a mut Self {
        // SAFETY: We're just reinterpreting the Unicorn as a UnicornEngine
        // This works because UnicornEngine is a transparent wrapper with only the Unicorn field
        unsafe { &mut *(emu as *mut Unicorn<'static, ()> as *mut Self) }
    }
    
    /// Get a mutable reference to the inner Unicorn for compatibility
    pub fn inner(&mut self) -> &mut Unicorn<'static, ()> {
        &mut self.emu
    }
    
    fn convert_register(reg: X86Register) -> RegisterX86 {
        match reg {
            X86Register::RAX => RegisterX86::RAX,
            X86Register::RBX => RegisterX86::RBX,
            X86Register::RCX => RegisterX86::RCX,
            X86Register::RDX => RegisterX86::RDX,
            X86Register::RSI => RegisterX86::RSI,
            X86Register::RDI => RegisterX86::RDI,
            X86Register::RBP => RegisterX86::RBP,
            X86Register::RSP => RegisterX86::RSP,
            X86Register::R8 => RegisterX86::R8,
            X86Register::R9 => RegisterX86::R9,
            X86Register::R10 => RegisterX86::R10,
            X86Register::R11 => RegisterX86::R11,
            X86Register::R12 => RegisterX86::R12,
            X86Register::R13 => RegisterX86::R13,
            X86Register::R14 => RegisterX86::R14,
            X86Register::R15 => RegisterX86::R15,
            X86Register::RIP => RegisterX86::RIP,
            X86Register::RFLAGS => RegisterX86::RFLAGS,
            X86Register::CS => RegisterX86::CS,
            X86Register::DS => RegisterX86::DS,
            X86Register::ES => RegisterX86::ES,
            X86Register::FS => RegisterX86::FS,
            X86Register::GS => RegisterX86::GS,
            X86Register::SS => RegisterX86::SS,
        }
    }
    
}

impl EmulatorEngine for UnicornEngine {
    fn reg_read(&mut self, reg: X86Register) -> Result<u64, EmulatorError> {
        self.emu.reg_read(Self::convert_register(reg))
            .map_err(|_| EmulatorError::RegisterRead)
    }
    
    fn reg_write(&mut self, reg: X86Register, value: u64) -> Result<(), EmulatorError> {
        self.emu.reg_write(Self::convert_register(reg), value)
            .map_err(|_| EmulatorError::RegisterWrite)
    }
    
    fn mem_read(&mut self, address: u64, buf: &mut [u8]) -> Result<(), EmulatorError> {
        self.emu.mem_read(address, buf)
            .map_err(|_| EmulatorError::MemoryRead)
    }
    
    fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), EmulatorError> {
        self.emu.mem_write(address, data)
            .map_err(|_| EmulatorError::MemoryWrite)
    }
    
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), EmulatorError> {
        use unicorn_engine::Permission;
        let mut uc_perms = Permission::NONE;
        if perms & 1 != 0 {
            uc_perms |= Permission::READ;
        }
        if perms & 2 != 0 {
            uc_perms |= Permission::WRITE;
        }
        if perms & 4 != 0 {
            uc_perms |= Permission::EXEC;
        }
        self.emu.mem_map(address, size, uc_perms)
            .map_err(|_| EmulatorError::InvalidMemory)
    }
    
    fn mem_unmap(&mut self, address: u64, size: usize) -> Result<(), EmulatorError> {
        self.emu.mem_unmap(address, size)
            .map_err(|_| EmulatorError::InvalidMemory)
    }
    
    fn mem_protect(&mut self, address: u64, size: usize, perms: u32) -> Result<(), EmulatorError> {
        use unicorn_engine::Permission;
        let mut uc_perms = Permission::NONE;
        if perms & 1 != 0 {
            uc_perms |= Permission::READ;
        }
        if perms & 2 != 0 {
            uc_perms |= Permission::WRITE;
        }
        if perms & 4 != 0 {
            uc_perms |= Permission::EXEC;
        }
        self.emu.mem_protect(address, size, uc_perms)
            .map_err(|_| EmulatorError::InvalidMemory)
    }
    
    fn mem_regions(&mut self) -> Result<Vec<(u64, u64)>, EmulatorError> {
        self.emu.mem_regions()
            .map(|regions| regions.into_iter().map(|r| (r.begin, r.end)).collect())
            .map_err(|_| EmulatorError::Other("Failed to get memory regions".to_string()))
    }
    
    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<(), EmulatorError> {
        self.emu.emu_start(begin, until, timeout, count)
            .map_err(|e| EmulatorError::Other(format!("{:?}", e)))
    }
    
    fn emu_stop(&mut self) -> Result<(), EmulatorError> {
        self.emu.emu_stop()
            .map_err(|e| EmulatorError::Other(format!("{:?}", e)))
    }
    
    fn add_code_hook(
        &mut self,
        _begin: u64,
        _end: u64,
        _callback: CodeHookCallback,
    ) -> Result<HookHandle, EmulatorError> {
        // We don't use this - hooks are set up directly on Unicorn
        Err(EmulatorError::Other("Use Unicorn hooks directly".to_string()))
    }
    
    fn add_mem_hook(
        &mut self,
        _hook_type: HookType,
        _begin: u64,
        _end: u64,
        _callback: MemHookCallback,
    ) -> Result<HookHandle, EmulatorError> {
        // We don't use this - hooks are set up directly on Unicorn
        Err(EmulatorError::Other("Use Unicorn hooks directly".to_string()))
    }
    
    fn remove_hook(&mut self, _handle: HookHandle) -> Result<(), EmulatorError> {
        // We don't use this - hooks are set up directly on Unicorn
        Err(EmulatorError::Other("Use Unicorn hooks directly".to_string()))
    }
    
    fn as_unicorn(&mut self) -> Option<&mut unicorn_engine::Unicorn<'static, ()>> {
        Some(&mut self.emu)
    }
}