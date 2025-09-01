pub const MOCK_FUNCTION_BASE: u64 = 0x7F000000;
pub const MOCK_FUNCTION_SIZE: usize = 0x100000;
pub const MOCK_FUNCTION_SPACING: u64 = 0x10;
pub const SYSTEM_DLL_BASE: u64 = 0x7FF000000000;

// DLL reason codes for DllMain
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;
pub const DLL_PROCESS_DETACH: u32 = 0;
