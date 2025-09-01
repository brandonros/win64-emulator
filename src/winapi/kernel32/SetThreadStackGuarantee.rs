/*
SetThreadStackGuarantee function (processthreadsapi.h)
02/06/2024
Sets the minimum size of the stack associated with the calling thread or fiber that will be available during any stack overflow exceptions. This is useful for handling stack overflow exceptions; the application can safely use the specified number of bytes during exception handling.

Syntax
C++

Copy
BOOL SetThreadStackGuarantee(
  [in, out] PULONG StackSizeInBytes
);
Parameters
[in, out] StackSizeInBytes

The size of the stack, in bytes. On return, this value is set to the size of the previous stack, in bytes.

If this parameter is 0 (zero), the function succeeds and the parameter contains the size of the current stack.

If the specified size is less than the current size, the function succeeds but ignores this request. Therefore, you cannot use this function to reduce the size of the stack.

This value cannot be larger than the reserved stack size.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.
*/