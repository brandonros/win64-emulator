/*
GetSystemFirmwareTable function (sysinfoapi.h)
02/15/2023
Retrieves the specified firmware table from the firmware table provider.

Syntax
C++

Copy
UINT GetSystemFirmwareTable(
  [in]  DWORD FirmwareTableProviderSignature,
  [in]  DWORD FirmwareTableID,
  [out] PVOID pFirmwareTableBuffer,
  [in]  DWORD BufferSize
);
Parameters
[in] FirmwareTableProviderSignature

The identifier of the firmware table provider to which the query is to be directed. This parameter can be one of the following values.

Value	Meaning
'ACPI'	The ACPI firmware table provider.
'FIRM'	The raw firmware table provider.
'RSMB'	The raw SMBIOS firmware table provider.
[in] FirmwareTableID

The identifier of the firmware table. This identifier is little endian, you must reverse the characters in the string.

For example, FACP is an ACPI provider, as described in the Signature field of the DESCRIPTION_HEADER structure in the ACPI specification (see the Advanced Configuration and Power Interface (ACPI) Specification. Therefore, use 'PCAF' to specify the FACP table, as shown in the following example:

retVal = GetSystemFirmwareTable('ACPI', 'PCAF', pBuffer, BUFSIZE);

For more information, see the Remarks section of the EnumSystemFirmwareTables function.

[out] pFirmwareTableBuffer

A pointer to a buffer that receives the requested firmware table. If this parameter is NULL, the return value is the required buffer size.

For more information on the contents of this buffer, see the Remarks section.

[in] BufferSize

The size of the pFirmwareTableBuffer buffer, in bytes.

Return value
If the function succeeds, the return value is the number of bytes written to the buffer. This value will always be less than or equal to BufferSize.

If the function fails because the buffer is not large enough, the return value is the required buffer size, in bytes. This value is always greater than BufferSize.

If the function fails for any other reason, the return value is zero. To get extended error information, call GetLastError.

Remarks
Starting with Windows 10, version 1803, Universal Windows apps can access the System Management BIOS (SMBIOS) information by declaring the smbios restricted capability in the app manifest. See Access SMBIOS information from a Universal Windows App for details. Only raw SMBIOS (RSMB) firmware tables can be accessed from a Universal Windows app.

As of Windows Server 2003 with Service Pack 1 (SP1), applications cannot access the \Device\PhysicalMemory object. Access to this object is limited to kernel-mode drivers. This change affects applications read System Management BIOS (SMBIOS) or other BIOS data stored in the lowest 1MB of physical memory. Applications have the following alternatives to read data from low physical memory:

Retrieve the SMBIOS properties using WMI. Many individual properties are contained in the Win32 classes. You can also retrieve the raw SMBIOS data in a single buffer using the MSSMBios_RawSMBiosTables class.
Use the GetSystemFirmwareTable function to read the raw SMBIOS firmware table.
There is no way for applications to write to low physical memory.
The raw SMBIOS table provider ('RSMB') retrieves the contents of the raw SMBIOS firmware table. The pFirmwareTableBuffer buffer receives the following data:

C++

Copy
#include <windows.h>

struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[];
};

The raw firmware table provider ('FIRM') retrieves the contents of the specified physical address range. The function returns the size of the address range.

The ACPI table provider ('ACPI') retrieves the contents of the specified ACPI table. Because OEMs can include ACPI firmware tables that are not listed in the ACPI specification, you should first call EnumSystemFirmwareTables to enumerate all ACPI tables that are currently on the system.

For ACPI, if the system contains multiple tables with the same name, they are all enumerated with EnumSystemFirmwareTables. However, GetSystemFirmwareTable retrieves only the first table in the list with this name.

Examples
The following example illustrates retrieving the SMBIOS table.

C++

Copy
DWORD error = ERROR_SUCCESS;
DWORD smBiosDataSize = 0;
RawSMBIOSData* smBiosData = NULL; // Defined in this link
DWORD bytesWritten = 0;

// Query size of SMBIOS data.
smBiosDataSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);

// Allocate memory for SMBIOS data
smBiosData = (RawSMBIOSData*) HeapAlloc(GetProcessHeap(), 0, smBiosDataSize);
if (!smBiosData) {
    error = ERROR_OUTOFMEMORY;
    goto exit;
}

// Retrieve the SMBIOS table
bytesWritten = GetSystemFirmwareTable('RSMB', 0, smBiosData, smBiosDataSize);

if (bytesWritten != smBiosDataSize) {
    error = ERROR_INVALID_DATA;
    goto exit;
}

// Process the SMBIOS data and free the memory under an exit label

*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RawSMBIOSData {
    used20_calling_method: u8,
    smbios_major_version: u8,
    smbios_minor_version: u8,
    dmi_revision: u8,
    length: u32,
    // SMBIOSTableData follows in memory
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SMBIOSHeader {
    type_: u8,
    length: u8,
    handle: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SystemInfo {
    header: SMBIOSHeader,
    manufacturer: u8,      // String index
    product_name: u8,      // String index
    version: u8,           // String index
    serial_number: u8,     // String index
    uuid: [u8; 16],
    wake_up_type: u8,
    sku_number: u8,        // String index
    family: u8,            // String index
}

fn create_mock_smbios_table() -> Vec<u8> {
    let mut table_data = Vec::new();
    
    // Create System Information structure (Type 1)
    let sys_info = SystemInfo {
        header: SMBIOSHeader {
            type_: 1,  // System Information
            length: std::mem::size_of::<SystemInfo>() as u8,
            handle: 0x0001,
        },
        manufacturer: 1,     // Index to first string
        product_name: 2,     // Index to second string
        version: 3,          // Index to third string
        serial_number: 4,    // Index to fourth string
        uuid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        wake_up_type: 6,     // Power switch
        sku_number: 5,       // Index to fifth string
        family: 6,           // Index to sixth string
    };
    
    // Convert struct to bytes
    let sys_info_bytes = unsafe {
        std::slice::from_raw_parts(
            &sys_info as *const SystemInfo as *const u8,
            std::mem::size_of::<SystemInfo>(),
        )
    };
    table_data.extend_from_slice(sys_info_bytes);
    
    // Add string data (null-terminated strings)
    let strings = [
        "ACME Corporation\0",      // 1: Manufacturer
        "Generic Computer\0",      // 2: Product Name
        "1.0\0",                  // 3: Version
        "ABC123456789\0",         // 4: Serial Number
        "Standard\0",             // 5: SKU Number
        "Desktop\0",              // 6: Family
    ];
    
    for string in &strings {
        table_data.extend_from_slice(string.as_bytes());
    }
    
    // SMBIOS entries end with double null terminator
    table_data.push(0x00);
    
    // Optionally add more SMBIOS structures here (BIOS Info, etc.)
    
    // Add end-of-table marker (Type 127)
    let end_marker = SMBIOSHeader {
        type_: 127,  // End-of-Table
        length: 4,   // Just the header
        handle: 0xFFFF,
    };
    
    let end_marker_bytes = unsafe {
        std::slice::from_raw_parts(
            &end_marker as *const SMBIOSHeader as *const u8,
            std::mem::size_of::<SMBIOSHeader>(),
        )
    };
    table_data.extend_from_slice(end_marker_bytes);
    table_data.push(0x00); // Double null terminator for end marker
    table_data.push(0x00);
    
    table_data
}

pub fn GetSystemFirmwareTable(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let provider_signature = emu.reg_read(RegisterX86::RCX)? as u32;
    let table_id = emu.reg_read(RegisterX86::RDX)? as u32;
    let buffer_ptr = emu.reg_read(RegisterX86::R8)?;
    let buffer_size = emu.reg_read(RegisterX86::R9)? as u32;
    
    // Convert signature to string for logging
    let provider_bytes = provider_signature.to_le_bytes();
    let provider_str = std::str::from_utf8(&provider_bytes).unwrap_or("????");
    let table_bytes = table_id.to_le_bytes();
    let table_str = std::str::from_utf8(&table_bytes).unwrap_or("????");
    
    log::info!(
        "[GetSystemFirmwareTable] Provider: '{}' (0x{:08x}), TableID: '{}' (0x{:08x}), Buffer: 0x{:x}, Size: {}",
        provider_str, provider_signature, table_str, table_id, buffer_ptr, buffer_size
    );
    
    // Handle RSMB (Raw SMBIOS) provider
    if provider_signature == 0x52534D42 {  // 'RSMB' in little endian
        // Create mock SMBIOS table data
        let mock_table_data = create_mock_smbios_table();
        let header_size = std::mem::size_of::<RawSMBIOSData>() as u32;
        let total_size = header_size + mock_table_data.len() as u32;
        
        // Check if this is a size query (buffer is NULL)
        if buffer_ptr == 0 {
            log::info!("[GetSystemFirmwareTable] Size query - returning {} bytes", total_size);
            emu.reg_write(RegisterX86::RAX, total_size as u64)?;
            return Ok(());
        }
        
        // Check if buffer is large enough
        if buffer_size < total_size {
            log::warn!("[GetSystemFirmwareTable] Buffer too small: {} < {}", buffer_size, total_size);
            emu.reg_write(RegisterX86::RAX, total_size as u64)?;
            return Ok(());
        }
        
        // Create and write RawSMBIOSData structure
        let smbios_header = RawSMBIOSData {
            used20_calling_method: 0x00,
            smbios_major_version: 0x03,
            smbios_minor_version: 0x04,
            dmi_revision: 0x00,
            length: mock_table_data.len() as u32,
        };
        
        // Write the header struct
        memory::write_struct(emu, buffer_ptr, &smbios_header)?;
        
        // Write the actual SMBIOS table data after the header
        let table_data_offset = buffer_ptr + header_size as u64;
        emu.mem_write(table_data_offset, &mock_table_data)?;
        
        log::info!(
            "[GetSystemFirmwareTable] Wrote {} bytes total ({} header + {} table data)",
            total_size, header_size, mock_table_data.len()
        );
        emu.reg_write(RegisterX86::RAX, total_size as u64)?;
        
    } else {
        // For other providers, panic (not supported)
        panic!("[GetSystemFirmwareTable] Unsupported provider: '{}'", provider_str);
        //emu.reg_write(RegisterX86::RAX, 0)?;
    }
    
    Ok(())
}
