use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use windows_sys::Win32::System::Variant::*;

/*
VariantClear function (oleauto.h)
02/22/2024
Clears a variant.

Syntax
C++

Copy
HRESULT VariantClear(
  [in, out] VARIANTARG *pvarg
);
Parameters
[in, out] pvarg

The variant to clear.

Return value
This function can return one of these values.

Return code	Description
S_OK
Success.
DISP_E_ARRAYISLOCKED
The variant contains an array that is locked.
DISP_E_BADVARTYPE
The variant type is not a valid type of variant.
E_INVALIDARG
One of the arguments is not valid.
Remarks
Use this function to clear variables of type VARIANTARG (or VARIANT) before the memory containing the VARIANTARG is freed (as when a local variable goes out of scope).

The function clears a VARIANTARG by setting the vt field to VT_EMPTY. The current contents of the VARIANTARG are released first. If the vtfield is VT_BSTR, the string is freed. If the vtfield is VT_DISPATCH, the object is released. If the vt field has the VT_ARRAY bit set, the array is freed.

If the variant to be cleared is a COM object that is passed by reference, the vtfield of the pvargparameter is VT_DISPATCH | VT_BYREF or VT_UNKNOWN | VT_BYREF. In this case, VariantClear does not release the object. Because the variant being cleared is a pointer to a reference to an object, VariantClear has no way to determine if it is necessary to release the object. It is therefore the responsibility of the caller to release the object or not, as appropriate.

In certain cases, it may be preferable to clear a variant in code without calling VariantClear. For example, you can change the type of a VT_I4 variant to another type without calling this function. Safearrays of BSTR will have SysFreeString called on each element not VariantClear. However, you must call VariantClear if a VT_type is received but cannot be handled. Safearrays of variant will also have VariantClear called on each member. Using VariantClear in these cases ensures that code will continue to work if Automation adds new variant types in the future.

Do not use VariantClear on uninitialized variants; use VariantInit to initialize a new VARIANTARG or VARIANT.

Variants containing arrays with outstanding references cannot be cleared. Attempts to do so will return an HRESULT containing DISP_E_ARRAYISLOCKED.

Examples
The following example shows how to clear an array of variants, where celt is the number of elements in the array.

C++

Copy
for(int i = 0; i < celt; ++i)
   VariantClear(&rgvar[i]);
*/

pub fn VariantClear(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HRESULT VariantClear(
    //   [in, out] VARIANTARG *pvarg  // RCX
    // )
    
    let pvarg = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[VariantClear] pvarg: 0x{:x}", pvarg);
    
    // HRESULT values
    const S_OK: u32 = 0x00000000;
    const E_INVALIDARG: u32 = 0x80070057;
    const DISP_E_BADVARTYPE: u32 = 0x80020008;
    const DISP_E_ARRAYISLOCKED: u32 = 0x8002000D;
    
    // Check for NULL pointer
    if pvarg == 0 {
        log::error!("[VariantClear] NULL pvarg pointer");
        emu.reg_write(X86Register::RAX, E_INVALIDARG as u64)?;
        return Ok(());
    }
    
    // VARIANT structure is properly defined in windows_sys
    // The VARENUM constants are also provided by windows_sys
    
    // Read the vt field (first 2 bytes) - VARENUM type
    let mut vt_bytes = [0u8; 2];
    emu.mem_read(pvarg, &mut vt_bytes)?;
    let vt = u16::from_le_bytes(vt_bytes);
    
    log::info!("[VariantClear] Current variant type (vt): 0x{:04x}", vt);
    
    // Extract base type without flags
    let base_type = vt & 0x0FFF;
    let is_byref = (vt & VT_BYREF as u16) != 0;
    let is_array = (vt & VT_ARRAY as u16) != 0;
    
    // Log the variant type for debugging
    let type_name = match base_type {
        x if x == VT_EMPTY as u16 => "VT_EMPTY",
        x if x == VT_NULL as u16 => "VT_NULL",
        x if x == VT_I2 as u16 => "VT_I2",
        x if x == VT_I4 as u16 => "VT_I4",
        x if x == VT_R4 as u16 => "VT_R4",
        x if x == VT_R8 as u16 => "VT_R8",
        x if x == VT_CY as u16 => "VT_CY",
        x if x == VT_DATE as u16 => "VT_DATE",
        x if x == VT_BSTR as u16 => "VT_BSTR",
        x if x == VT_DISPATCH as u16 => "VT_DISPATCH",
        x if x == VT_ERROR as u16 => "VT_ERROR",
        x if x == VT_BOOL as u16 => "VT_BOOL",
        x if x == VT_VARIANT as u16 => "VT_VARIANT",
        x if x == VT_UNKNOWN as u16 => "VT_UNKNOWN",
        x if x == VT_DECIMAL as u16 => "VT_DECIMAL",
        x if x == VT_I1 as u16 => "VT_I1",
        x if x == VT_UI1 as u16 => "VT_UI1",
        x if x == VT_UI2 as u16 => "VT_UI2",
        x if x == VT_UI4 as u16 => "VT_UI4",
        x if x == VT_I8 as u16 => "VT_I8",
        x if x == VT_UI8 as u16 => "VT_UI8",
        x if x == VT_INT as u16 => "VT_INT",
        x if x == VT_UINT as u16 => "VT_UINT",
        x if x == VT_LPSTR as u16 => "VT_LPSTR",
        x if x == VT_LPWSTR as u16 => "VT_LPWSTR",
        _ => "Unknown"
    };
    
    log::info!("[VariantClear] Variant type: {} (0x{:04x})", type_name, base_type);
    if is_byref {
        log::info!("[VariantClear] Variant is BYREF");
    }
    if is_array {
        log::info!("[VariantClear] Variant contains an array");
    }
    
    // Check for invalid variant type
    if base_type > 0xFF && base_type != VT_ARRAY as u16 {
        log::error!("[VariantClear] Invalid variant type: 0x{:04x}", vt);
        emu.reg_write(X86Register::RAX, DISP_E_BADVARTYPE as u64)?;
        return Ok(());
    }
    
    // Handle special cases based on variant type
    match base_type {
        x if x == VT_EMPTY as u16 => {
            log::info!("[VariantClear] Variant is already empty");
        },
        x if x == VT_BSTR as u16 => {
            if !is_byref {
                // Read the BSTR pointer from the union (offset 0x08)
                let mut bstr_bytes = [0u8; 8];
                emu.mem_read(pvarg + 0x08, &mut bstr_bytes)?;
                let bstr = u64::from_le_bytes(bstr_bytes);
                
                if bstr != 0 {
                    log::info!("[VariantClear] Would free BSTR at 0x{:x}", bstr);
                    // In a real implementation, we would call SysFreeString here
                }
            }
        },
        x if x == VT_DISPATCH as u16 || x == VT_UNKNOWN as u16 => {
            if !is_byref {
                // Read the interface pointer from the union (offset 0x08)
                let mut ptr_bytes = [0u8; 8];
                emu.mem_read(pvarg + 0x08, &mut ptr_bytes)?;
                let ptr = u64::from_le_bytes(ptr_bytes);
                
                if ptr != 0 {
                    let iface_type = if base_type == VT_DISPATCH as u16 { "IDispatch" } else { "IUnknown" };
                    log::info!("[VariantClear] Would release {} interface at 0x{:x}", iface_type, ptr);
                    // In a real implementation, we would call Release() on the interface
                }
            } else {
                log::info!("[VariantClear] Skipping release for BYREF COM object");
            }
        },
        _ => {
            if is_array {
                log::info!("[VariantClear] Would free SAFEARRAY");
                // In a real implementation, we would call SafeArrayDestroy
                
                // For now, just check if it's locked (mock)
                // In reality, we'd need to check the actual array structure
                if false {  // Mock check - never locked in our simulation
                    log::error!("[VariantClear] Array is locked");
                    emu.reg_write(X86Register::RAX, DISP_E_ARRAYISLOCKED as u64)?;
                    return Ok(());
                }
            } else {
                log::info!("[VariantClear] Simple type - no special cleanup needed");
            }
        }
    }
    
    // Clear the variant by setting vt to VT_EMPTY
    let vt_empty = (VT_EMPTY as u16).to_le_bytes();
    emu.mem_write(pvarg, &vt_empty)?;
    
    // Clear the reserved fields (optional, but good practice)
    let zeros = [0u8; 6];
    emu.mem_write(pvarg + 2, &zeros)?;
    
    // Clear the union data (8 bytes on x64)
    let union_zeros = [0u8; 8];
    emu.mem_write(pvarg + 8, &union_zeros)?;
    
    log::info!("[VariantClear] Variant cleared successfully");
    log::warn!("[VariantClear] Mock implementation - resource cleanup simulated");
    
    // Return S_OK
    emu.reg_write(X86Register::RAX, S_OK as u64)?;
    
    Ok(())
}