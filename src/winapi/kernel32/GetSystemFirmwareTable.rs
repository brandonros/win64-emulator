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
use std::fs;

fn load_firmware_table_from_bin() -> Result<Vec<u8>, std::io::Error> {
    // Load the raw firmware table data from your .bin file
    fs::read("mock_files/firmware_table.bin") // Adjust path as needed
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
        // Load the complete raw firmware table data from .bin file
        let firmware_table_data = match load_firmware_table_from_bin() {
            Ok(data) => {
                log::info!("[GetSystemFirmwareTable] Loaded {} bytes from firmware_table.bin", data.len());
                data
            },
            Err(e) => {
                log::error!("[GetSystemFirmwareTable] Failed to load firmware_table.bin: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        };
        
        // Check if this is a size query (buffer is NULL)
        if buffer_ptr == 0 {
            log::info!("[GetSystemFirmwareTable] Size query - returning {} bytes", firmware_table_data.len());
            emu.reg_write(RegisterX86::RAX, firmware_table_data.len() as u64)?;
            return Ok(());
        }
        
        // Check if buffer is large enough
        if buffer_size < firmware_table_data.len() as u32 {
            log::warn!("[GetSystemFirmwareTable] Buffer too small: {} < {}", buffer_size, firmware_table_data.len());
            emu.reg_write(RegisterX86::RAX, firmware_table_data.len() as u64)?;
            return Ok(());
        }
        
        // Write the raw firmware table data directly to the buffer
        emu.mem_write(buffer_ptr, &firmware_table_data)?;
        
        log::info!(
            "[GetSystemFirmwareTable] Wrote {} bytes of raw firmware table data",
            firmware_table_data.len()
        );
        emu.reg_write(RegisterX86::RAX, firmware_table_data.len() as u64)?;
        
    } else {
        // For other providers, return error
        log::warn!("[GetSystemFirmwareTable] Unsupported provider: '{}'", provider_str);
        emu.reg_write(RegisterX86::RAX, 0)?;
    }
    
    Ok(())
}
