use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::{emulation::iat::IAT_FUNCTION_MAP, pe::constants::*, winapi};

#[derive(Debug, Clone, Copy)]
enum CallType {
    Call,       // CALL instruction - needs return address pushed
    Jump,       // JMP instruction - no return address
    RetTrampoline, // RET used as trampoline - no return address
}

impl CallType {
    fn should_push_return_address(&self) -> bool {
        matches!(self, CallType::Call)
    }
    
    fn should_pop_return_address(&self) -> bool {
        // Only pop if we pushed (CALL instructions)
        matches!(self, CallType::Call)
    }
    
    fn as_str(&self) -> &str {
        match self {
            CallType::Call => "CALL",
            CallType::Jump => "JMP",
            CallType::RetTrampoline => "RET->",
        }
    }
}

pub fn intercept_iat_call<D>(emu: &mut Unicorn<D>, instruction: Instruction, instruction_size: u32, addr: u64, count: u64) {
    let mnemonic = instruction.mnemonic();
    
    // Handle CALL, JMP, and RET instructions
    if (mnemonic == Mnemonic::Call || mnemonic == Mnemonic::Jmp) && instruction.op_count() > 0 {
        let instruction_type = if mnemonic == Mnemonic::Call { "CALL" } else { "JMP" };
        //log:trace!("{} instruction detected at 0x{:x}: {:?}", instruction_type, addr, instruction);
        
        // Add detailed logging about the call/jmp type
        match instruction.op0_kind() {
            OpKind::Memory => {
                //log:trace!("=== INSTRUCTION DECODE DEBUG ===");
                //log:trace!("Hook triggered at address: 0x{:x}", addr);
                //log:trace!("Instruction size parameter: {}", instruction_size);
                //log:trace!("Decoded instruction length: {}", instruction.len());
                //log:trace!("Decoded instruction: {}", instruction);

                //log:trace!("=== INDIRECT {} ANALYSIS at 0x{:x} ===", instruction_type, addr);
                //log:trace!("Instruction: {}", instruction);
                //log:trace!("Op0 kind: Memory (indirect {})", instruction_type.to_lowercase());
                
                if let Some(target_addr) = get_indirect_call_target(&instruction, instruction_size, emu, addr) {
                    //log:trace!("Calculated target address: 0x{:x}", target_addr);
                    
                    // Check if the target address is in valid memory range
                    if !is_valid_memory_address(emu, target_addr) {
                        log::error!("Target address 0x{:x} is not in valid memory range!", target_addr);
                        return;
                    }
                    
                    // Read the function pointer from the calculated address
                    if let Some(func_ptr) = read_function_pointer(emu, target_addr) {
                        //log:trace!("✓ Successfully read function pointer 0x{:x} from [0x{:x}]", func_ptr, target_addr);
                        
                        // Check if this points to our mock function area (IAT call)
                        if is_mock_function_address(func_ptr) {
                            //log:trace!("✓ Detected IAT call through [0x{:016x}] -> 0x{:016x} (in mock range)", target_addr, func_ptr);
                            let call_type = if mnemonic == Mnemonic::Call { CallType::Call } else { CallType::Jump };
                            handle_iat_function_call(func_ptr, emu, addr, &instruction, count, call_type);
                        } else {
                            //log:trace!("✗ Function pointer 0x{:x} is NOT in mock function range, skipping IAT handling", func_ptr);
                        }
                    } else {
                        log::error!("✗ Failed to read function pointer from [0x{:x}]", target_addr);
                    }
                } else {
                    log::warn!("Failed to calculate target address for indirect {} at 0x{:x}", instruction_type.to_lowercase(), addr);
                }
            }
            OpKind::NearBranch64 => {
                // TODO: how do we know it's not IAT?
                //log:trace!("Direct {} to 0x{:x} (not IAT)", instruction_type.to_lowercase(), instruction.near_branch64());
            }
            OpKind::Register => {
                //log:trace!("Register {} - register: {:?}", instruction_type.to_lowercase(), instruction.op0_register());
                
                // Get the value from the register
                if let Some(unicorn_reg) = map_iced_to_unicorn_register(instruction.op0_register()) {
                    let register_value = emu.reg_read(unicorn_reg).unwrap();
                    //log:trace!("Register value: 0x{:x}", register_value);
                    
                    // Check if this is a call/jump to a mock function address
                    if is_mock_function_address(register_value) {
                        //log:trace!("✓ Register contains mock function address, handling as IAT call");
                        let call_type = if mnemonic == Mnemonic::Call { CallType::Call } else { CallType::Jump };
                        handle_iat_function_call(register_value, emu, addr, &instruction, count, call_type);
                    } else {
                        //log:trace!("✗ Register value 0x{:x} is not a mock function address", register_value);
                    }
                } else {
                    log::warn!("Unsupported register for IAT check: {:?}", instruction.op0_register());
                }
            }
            _ => {
                //log:trace!("Other {} type: {:?}", instruction_type.to_lowercase(), instruction.op0_kind());
            }
        }
    }
    
    // Handle RET instructions - check if they're returning to a mock function address
    if mnemonic == Mnemonic::Ret {
        //log:trace!("RET instruction detected at 0x{:x}", addr);
        
        // Read the return address from the stack (what RET will pop and jump to)
        let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
        if let Some(return_addr) = read_function_pointer(emu, rsp) {
            //log:trace!("RET will return to address: 0x{:x}", return_addr);
            
            // Check if the return address is a mock function address
            if is_mock_function_address(return_addr) {
                //log:trace!("✓ RET returning to mock function address, handling as IAT call");
                
                // Pop the return address from stack (simulate the RET)
                emu.reg_write(RegisterX86::RSP, rsp + 8).unwrap();
                
                // RET to IAT function acts as a trampoline (no return address to push)
                handle_iat_function_call(return_addr, emu, addr, &instruction, count, CallType::RetTrampoline);
            } else {
                //log:trace!("✗ RET return address 0x{:x} is not a mock function address", return_addr);
            }
        } else {
            //log:trace!("Failed to read return address from stack at RSP 0x{:x}", rsp);
        }
    }
}

/// Get the target address for an indirect call instruction
fn get_indirect_call_target<D>(
    instruction: &Instruction,
    instruction_size: u32,
    emu: &mut Unicorn<D>,
    addr: u64,
) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::Memory => {
            let target = calculate_effective_address(instruction, instruction_size, emu, addr);
            //log:trace!("Effective address calculated: 0x{:x}", target);
            Some(target)
        }
        _ => {
            //log:trace!("Not a memory operand, skipping IAT check");
            None
        }
    }
}

/// Calculate the effective address for a memory operand
fn calculate_effective_address<D>(
    instruction: &Instruction,
    _instruction_size: u32,
    emu: &mut Unicorn<D>,
    addr: u64,
) -> u64 {
    //log:trace!("--- EFFECTIVE ADDRESS CALCULATION ---");
    //log:trace!("Instruction: {}", instruction);
    //log:trace!("Instruction bytes/encoding: {:?}", instruction);
    //log:trace!("Instruction len: {}", instruction.len());
    //log:trace!("Current address: 0x{:x}", addr);
    //log:trace!("Memory base: {:?}", instruction.memory_base());
    //log:trace!("Memory index: {:?}", instruction.memory_index());
    //log:trace!("Memory scale: {}", instruction.memory_index_scale());
    //log:trace!("Memory displacement32: 0x{:x}", instruction.memory_displacement32());
    //log:trace!("Memory displacement64: 0x{:x}", instruction.memory_displacement64());
    //log:trace!("Is IP relative: {}", instruction.is_ip_rel_memory_operand());
    
    // Check if the instruction uses RIP-relative memory addressing
    if instruction.is_ip_rel_memory_operand() {
        // For x64, we should check if there's a 64-bit displacement first
        let displacement64 = instruction.memory_displacement64();
        
        if displacement64 != 0 {
            // Use the 64-bit displacement directly (absolute address in x64)
            //log:trace!("✓ RIP-relative with 64-bit displacement (absolute address)");
            //log:trace!("  Displacement64: 0x{:016x}", displacement64);
            //log:trace!("  Effective address: 0x{:016x}", displacement64);
            return displacement64;
        }
        
        // Fall back to 32-bit RIP-relative calculation
        let displacement_u32 = instruction.memory_displacement32();
        let displacement = displacement_u32 as i32;  // Treat as signed!
        let rip_value = addr + instruction.len() as u64;
        let effective_addr = (rip_value as i64 + displacement as i64) as u64;
        
        //log:trace!("✓ RIP-relative addressing detected (32-bit displacement)");
        //log:trace!("  Current RIP: 0x{:016x}", addr);
        //log:trace!("  Instruction length: {}", instruction.len());
        //log:trace!("  Next RIP: 0x{:016x}", rip_value);
        //log:trace!("  Displacement (unsigned): 0x{:08x} ({})", displacement_u32, displacement_u32);
        //log:trace!("  Displacement (signed): 0x{:08x} ({})", displacement, displacement);
        //log:trace!("  Calculation: 0x{:016x} + {} = 0x{:016x}", rip_value, displacement, effective_addr);
        //log:trace!("  Effective address: 0x{:016x}", effective_addr);
        
        return effective_addr;
    }

    // For RIP-relative addressing (common in x64)
    if instruction.memory_base() == Register::RIP {
        let displacement = instruction.memory_displacement32() as i32;
        let rip_value = addr + instruction.len() as u64;
        let effective_addr = (rip_value as i64 + displacement as i64) as u64;
        
        //log:trace!("✓ RIP-relative addressing (explicit RIP base):");
        //log:trace!("  Current RIP: 0x{:016x}", addr);
        //log:trace!("  Instruction length: {}", instruction.len());
        //log:trace!("  Next RIP: 0x{:016x}", rip_value);
        //log:trace!("  Displacement: 0x{:08x} ({})", displacement, displacement);
        //log:trace!("  Effective address: 0x{:016x}", effective_addr);
        
        return effective_addr;
    }
    
    // Direct absolute addressing - when there's no base and no index register
    if instruction.memory_base() == Register::None && 
       instruction.memory_index() == Register::None {
        // For x64, check if this uses 64-bit displacement (absolute address)
        let displacement64 = instruction.memory_displacement64();
        let displacement32 = instruction.memory_displacement32();
        
        if displacement64 != 0 {
            //log:trace!("✓ Direct absolute address (64-bit): 0x{:016x}", displacement64);
            return displacement64;
        }
        
        // If displacement64 is 0 but we have a 32-bit displacement,
        // it might be RIP-relative (depends on the encoding)
        if displacement32 != 0 {
            // This is likely RIP-relative addressing in x64
            // In x64, [disp32] is encoded as RIP+disp32
            let disp32 = displacement32 as i32;
            let rip_value = addr + instruction.len() as u64;
            let effective_addr = (rip_value as i64 + disp32 as i64) as u64;
            
            //log:trace!("✓ Implicit RIP-relative (x64 [disp32]):");
            //log:trace!("  Current RIP: 0x{:016x}", addr);
            //log:trace!("  Next RIP: 0x{:016x}", rip_value);
            //log:trace!("  Displacement32: 0x{:08x} (signed: {})", displacement32, disp32);
            //log:trace!("  Effective address: 0x{:016x}", effective_addr);
            
            return effective_addr;
        }
        
        //log:trace!("✓ Zero displacement - should not happen");
        return 0;
    }
    
    // Handle base + index + displacement
    let mut target_addr = 0u64;
    //log:trace!("✓ Complex addressing mode detected");
    
    // Get base register value if present
    if instruction.memory_base() != Register::None {
        let base_value = get_base_register_value(instruction.memory_base(), emu, addr, instruction);
        //log:trace!("  Base register {:?} = 0x{:016x}", instruction.memory_base(), base_value);
        target_addr = base_value;
    }
    
    // Add index register value if present
    if instruction.memory_index() != Register::None {
        let index_contribution = get_index_register_contribution(instruction, emu);
        //log:trace!("  Index contribution = 0x{:016x}", index_contribution);
        target_addr += index_contribution;
    }
    
    // Add displacement
    let displacement = instruction.memory_displacement64();
    let final_addr = (target_addr as i64 + displacement as i64) as u64;
    //log:trace!("  Displacement: 0x{:016x}", displacement);
    //log:trace!("  Final effective address: 0x{:016x}", final_addr);
    
    final_addr
}

/// Get the value of the base register
fn get_base_register_value<D>(
    base_reg: Register,
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
) -> u64 {
    if base_reg == Register::RIP {
        // RIP-relative addressing
        let rip_value = addr + instruction.len() as u64;
        //log:trace!("    RIP base register = 0x{:016x}", rip_value);
        return rip_value;
    }
    
    match map_iced_to_unicorn_register(base_reg) {
        Some(unicorn_reg) => {
            let value = emu.reg_read(unicorn_reg).unwrap();
            //log:trace!("    Base register {:?} = 0x{:016x}", base_reg, value);
            value
        }
        None => {
            log::warn!("    Unsupported base register: {:?}", base_reg);
            0
        }
    }
}

/// Calculate the contribution of the index register (value * scale)
fn get_index_register_contribution<D>(
    instruction: &Instruction,
    emu: &mut Unicorn<D>,
) -> u64 {
    let index_reg = match map_iced_to_unicorn_register(instruction.memory_index()) {
        Some(reg) => reg,
        None => {
            log::warn!("    Unsupported index register: {:?}", instruction.memory_index());
            return 0;
        }
    };
    
    let index_value = emu.reg_read(index_reg).unwrap();
    let scale = instruction.memory_index_scale();
    let contribution = index_value * scale as u64;
    
    //log:trace!("    Index register {:?} = 0x{:016x}, scale = {}, contribution = 0x{:016x}", instruction.memory_index(), index_value, scale, contribution);
    
    contribution
}

/// Map iced_x86 Register to unicorn RegisterX86
fn map_iced_to_unicorn_register(reg: Register) -> Option<RegisterX86> {
    match reg {
        Register::RAX => Some(RegisterX86::RAX),
        Register::RBX => Some(RegisterX86::RBX),
        Register::RCX => Some(RegisterX86::RCX),
        Register::RDX => Some(RegisterX86::RDX),
        Register::RSI => Some(RegisterX86::RSI),
        Register::RDI => Some(RegisterX86::RDI),
        Register::RBP => Some(RegisterX86::RBP),
        Register::RSP => Some(RegisterX86::RSP),
        Register::R8 => Some(RegisterX86::R8),
        Register::R9 => Some(RegisterX86::R9),
        Register::R10 => Some(RegisterX86::R10),
        Register::R11 => Some(RegisterX86::R11),
        Register::R12 => Some(RegisterX86::R12),
        Register::R13 => Some(RegisterX86::R13),
        Register::R14 => Some(RegisterX86::R14),
        Register::R15 => Some(RegisterX86::R15),
        _ => None,
    }
}

/// Handle an IAT function call with the given function pointer
fn handle_iat_function_call<D>(
    func_ptr: u64,
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
    count: u64,
    call_type: CallType
) {
    //log:trace!("=== IAT {} HANDLER ===", call_type.as_str());
    //log:trace!("Function pointer: 0x{:x}", func_ptr);
    
    // Look up and handle the API function
    if let Some((dll_name, func_name)) = lookup_iat_function(func_ptr) {
        log::info!("[{}:{:x}] 🔷 API {}: {}!{}", count, addr, call_type.as_str(), dll_name, func_name);
        execute_api_call(emu, addr, instruction, &dll_name, &func_name, call_type);
    } else {
        log::error!("✗ Mock function at 0x{:016x} not found in IAT_FUNCTION_MAP", func_ptr);
        log::error!("Available functions in IAT_FUNCTION_MAP:");
        let iat_map = IAT_FUNCTION_MAP.read().unwrap();
        for (addr, (dll, func)) in iat_map.iter() {
            log::error!("  0x{:016x} -> {}!{}", addr, dll, func);
        }
    }
}

/// Check if a memory address is valid/accessible
fn is_valid_memory_address<D>(emu: &mut Unicorn<D>, addr: u64) -> bool {
    let mut test_byte = [0u8; 1];
    emu.mem_read(addr, &mut test_byte).is_ok()
}

/// Read a 64-bit function pointer from memory
fn read_function_pointer<D>(emu: &mut Unicorn<D>, address: u64) -> Option<u64> {
    let mut func_ptr_bytes = [0u8; 8];
    match emu.mem_read(address, &mut func_ptr_bytes) {
        Ok(_) => {
            let value = u64::from_le_bytes(func_ptr_bytes);
            //log:trace!("  Memory read successful: [0x{:x}] = 0x{:016x}", address, value);
            Some(value)
        }
        Err(e) => {
            log::error!("  Memory read failed at 0x{:x}: {:?}", address, e);
            None
        }
    }
}

/// Check if an address points to the mock function area
fn is_mock_function_address(addr: u64) -> bool {
    let in_range = addr >= MOCK_FUNCTION_BASE && addr < MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    //log:trace!("Mock function check: 0x{:x} in range [0x{:x}, 0x{:x}) = {}", addr, MOCK_FUNCTION_BASE, MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64, in_range);
    in_range
}

/// Look up function information from the IAT function map
fn lookup_iat_function(func_ptr: u64) -> Option<(String, String)> {
    let result = IAT_FUNCTION_MAP
        .read()
        .unwrap()
        .get(&func_ptr)
        .map(|info| (info.0.clone(), info.1.clone()));
    
    match &result {
        Some((dll, func)) => {
            //log:trace!("✓ Found IAT function: 0x{:x} -> {}!{}", func_ptr, dll, func);
        }
        None => {
            log::warn!("✗ IAT function not found for address 0x{:x}", func_ptr);
        }
    }
    
    result
}

/// Execute an API call by setting up the stack and calling the handler
fn execute_api_call<D>(
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
    dll_name: &str,
    func_name: &str,
    call_type: CallType
) {
    //log:trace!("=== EXECUTING API CALL ===");
    //log:trace!("Function: {}!{}", dll_name, func_name);
    //log:trace!("Call type: {:?}", call_type);
    //log:trace!("Call address: 0x{:x}", addr);
    
    // Only push return address for CALL instructions
    if call_type.should_push_return_address() {
        let return_addr = addr + instruction.len() as u64;
        //log:trace!("Pushing return address: 0x{:x}", return_addr);
        push_return_address(emu, return_addr);
    }
    
    // Handle the API call
    match winapi::handle_winapi_call(emu, dll_name, func_name) {
        Ok(_) => {
            //log:trace!("✓ API call completed successfully");
            finalize_api_call(emu);
        }
        Err(err) => {
            log::error!("✗ API call failed: {:?}", err);
            panic!(
                "handle_winapi_call failed for {}!{}: {:?}",
                dll_name, func_name, err
            );
        }
    }
}

/// Push the return address onto the stack
fn push_return_address<D>(emu: &mut Unicorn<D>, return_addr: u64) {
    let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
    let new_rsp = rsp - 8;
    //log:trace!("Pushing return address 0x{:x} onto stack: RSP 0x{:x} -> 0x{:x}", return_addr, rsp, new_rsp);
    emu.reg_write(RegisterX86::RSP, new_rsp).unwrap();
    emu.mem_write(new_rsp, &return_addr.to_le_bytes()).unwrap();
}

/// Finalize API call by simulating the RET that would have happened
fn finalize_api_call<D>(emu: &mut Unicorn<D>) {
    //let rax = emu.reg_read(RegisterX86::RAX).unwrap();
    //log:trace!("Finalizing API call - RAX return value: 0x{:x}", rax);
    //log:trace!("Call type: {:?}", call_type);
    
    // ALWAYS simulate the API function's RET instruction
    // Real Windows API functions always end with RET
    
    // Read the return address from stack (what RET would pop)
    let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
    let mut ret_addr_bytes = [0u8; 8];
    emu.mem_read(rsp, &mut ret_addr_bytes).unwrap();
    let ret_addr_from_stack = u64::from_le_bytes(ret_addr_bytes);
    
    // Pop the stack (like RET would)
    emu.reg_write(RegisterX86::RSP, rsp + 8).unwrap();
    
    // Jump to the return address (like RET would)
    emu.reg_write(RegisterX86::RIP, ret_addr_from_stack).unwrap();
    
    //log:trace!("Simulated API RET: popped 0x{:x} from stack, RSP 0x{:x} -> 0x{:x}", 
    //    ret_addr_from_stack, rsp, rsp + 8);
}
