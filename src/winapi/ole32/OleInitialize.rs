/*
OleInitialize function (ole2.h)
10/12/2021
Initializes the COM library on the current apartment, identifies the concurrency model as single-thread apartment (STA), and enables additional functionality described in the Remarks section below. Applications must initialize the COM library before they can call COM library functions other than CoGetMalloc and memory allocation functions.

Syntax
C++

Copy
HRESULT OleInitialize(
  [in] LPVOID pvReserved
);
Parameters
[in] pvReserved

This parameter is reserved and must be NULL.

Return value
This function returns S_OK on success. Other possible values include the following.
*/