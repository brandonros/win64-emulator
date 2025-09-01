/*
RtlInitUnicodeString function (wdm.h)
02/22/2024
For more information, see the WdmlibRtlInitUnicodeStringEx function.

Syntax
C++

Copy
NTSYSAPI VOID RtlInitUnicodeString(
  [out]          PUNICODE_STRING         DestinationString,
  [in, optional] __drv_aliasesMem PCWSTR SourceString
);
Parameters
[out] DestinationString

For more information, see the WdmlibRtlInitUnicodeStringEx function.

[in, optional] SourceString

For more information, see the WdmlibRtlInitUnicodeStringEx function.

Return value
For more information, see the WdmlibRtlInitUnicodeStringEx function.

Remarks
The RTL_CONSTANT_STRING macro creates a string or Unicode string structure to hold a counted string.

STRING RTL_CONSTANT_STRING(
  [in]  PCSZ SourceString
);

UNICODE_STRING RTL_CONSTANT_STRING(
  [in]  PCWSTR SourceString
);
RTL_CONSTANT_STRING returns either a string structure or Unicode string structure.

The RTL_CONSTANT_STRING macro replaces the RtlInitAnsiString, RtlInitString, and RtlInitUnicodeString routines when passing a constant string.

You can use RTL_CONSTANT_STRING to initialize global variables.


*/