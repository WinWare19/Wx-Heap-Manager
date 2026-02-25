#pragma once

#define WX_HEAP_FLAG_NO_SERIALIZE 0x1
#define WX_HEAP_FLAG_GROWABLE 0x2
#define WX_HEAP_FLAG_GENERATE_EXCEPTIONS 0x4
#define WX_HEAP_FLAG_ZERO_MEMORY 0x8
#define WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE 0x40000
#define WX_HEAP_FLAG_LARGE_ALLOCATION 0x50000
#define WX_HEAP_FLAG_SUPPORT_FRAGMENTATION 0x60000
#define WX_HEAP_FLAG_SUPPORT_COALESCING 0x70000
#define WX_HEAP_FLAG_FREE_CHUNK 0x80000
#define WX_HEAP_FLAG_VALID_MASK (WX_HEAP_FLAG_NO_SERIALIZE | WX_HEAP_FLAG_GROWABLE | WX_HEAP_FLAG_GENERATE_EXCEPTIONS | WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE | WX_HEAP_FLAG_LARGE_ALLOCATION | WX_HEAP_FLAG_SUPPORT_FRAGMENTATION | WX_HEAP_FLAG_SUPPORT_COALESCING)

#define WX_HEAP_INITIAL_FREE_CHUNKS 0x14
#define WX_HEAP_DEFAULT_EXTENT_MAX_SIZE_IN_PAGES 0x3

#define WxZeroMemory(address, size) for(UINT i = 0x0; i < (size); i++) (address)[i] = 0x0

// ========================================================

// enums
typedef enum _WX_HEAP_INFORMATION_CLASS {
	WxHeapEnableFragmentation,
	WxHeapEnableTerminationOnCorruption,
	WxHeapEnableCoalescing
} WX_HEAP_INFORMATION_CLASS, * PWX_HEAP_INFORMATION_CLASS, * LPWX_HEAP_INFORMATION_CLASS;

// ========================================================

// EXPORTS
BOOLEAN __stdcall WxHeapManagerInit();
HANDLE __stdcall WxCreateHeap(DWORD, SIZE_T, SIZE_T);
BOOLEAN __stdcall WxDestroyHeap(HANDLE);
LPVOID __stdcall WxHeapAlloc(HANDLE, DWORD, SIZE_T);
LPVOID __stdcall WxHeapReAlloc(HANDLE, LPVOID, DWORD, SIZE_T);
BOOLEAN  __stdcall WxHeapFree(HANDLE, LPVOID);
HANDLE __stdcall GetProcessWxHeap();
BOOL __stdcall WxHeapSetInformation(HANDLE, WX_HEAP_INFORMATION_CLASS, LPVOID, SIZE_T);
