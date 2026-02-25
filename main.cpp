// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// ========================================================

// structs
typedef struct _WX_LIST_ENTRY {
	_WX_LIST_ENTRY* Flink, * Blink;
} WX_LIST_ENTRY, * PWX_LIST_ENTRY, * LPWX_LIST_ENTRY;
typedef struct _WX_HEAP_CHUNK_HEADER {
	WORD signature;
	WX_LIST_ENTRY list_entry, frontend_list_entry, coalescing_list_entry, * extent_list_entry;
	DWORD total_size, flags;
} WX_HEAP_CHUNK_HEADER, * PHWX_HEAP_CHUNK_HEADER, * LPWX_HEAP_CHUNK_HEADER;
typedef struct _WX_HEAP_EXTENT {
	WORD signature;
	LPBYTE base_address;
	DWORD total_size, commited_size, current_offset;
	WX_LIST_ENTRY list_entry;
	WX_LIST_ENTRY free_chunks_list_head, busy_chunks_list_head, coalescing_helper_list_head;
} WX_HEAP_EXTENT, * PWX_HEAP_EXTENT, * LPWX_HEAP_EXTENT;
typedef struct _WX_HEAP_FRONTEND {
	WORD signature;
	WX_LIST_ENTRY free_chunks[0xA];
} WX_HEAP_FRONTEND, * PWX_HEAP_FRONTEND, * LPWX_HEAP_FRONTEND;
typedef struct _WX_HEAP {
	WORD signature;
	DWORD flags;
	CRITICAL_SECTION sync_object;
	DWORD extents_count;
	WX_LIST_ENTRY extents_list_head, large_allocations;
	WX_HEAP_FRONTEND* frontend_allocator;
} WX_HEAP, * PWX_HEAP, * LPWX_HEAP;
typedef struct _WX_HEAP_LARGE_ALLOCATION {
	LPVOID address;
	SIZE_T size;
	WX_LIST_ENTRY list_entry;
} WX_HEAP_LARGE_ALLOCATION, * PWX_HEAP_LARGE_ALLOCATION, * LPWX_HEAP_LARGE_ALLOCATION;

// ========================================================

// Doubly Linked list functions
void __stdcall WxInitializeListHead(PWX_LIST_ENTRY);
void __stdcall WxInsertHeadList(PWX_LIST_ENTRY, PWX_LIST_ENTRY);
void __stdcall WxRemoveFromList(PWX_LIST_ENTRY);
void __stdcall WxRemoveInsertHeadList(PWX_LIST_ENTRY, PWX_LIST_ENTRY);

// Wx heap functions
BOOLEAN __stdcall WxInitializeHeapExtent(WX_HEAP_EXTENT*, LPBYTE, SIZE_T, SIZE_T);
BOOLEAN __stdcall WxInitializeHeapChunk(WX_HEAP_CHUNK_HEADER*, LPWX_LIST_ENTRY, DWORD, SIZE_T);
LPVOID __stdcall WxHeapAlloc(HANDLE, DWORD, SIZE_T);
LPVOID __stdcall WxHeapReAlloc(HANDLE, LPVOID, DWORD, SIZE_T);
BOOLEAN  __stdcall WxHeapFree(HANDLE, LPVOID);
BOOLEAN __stdcall WxCommitHeapExtent(WX_HEAP_EXTENT*, SIZE_T, BOOLEAN);
BOOLEAN __stdcall WxInitializeHeapFrontend(WX_HEAP_FRONTEND*);
BOOLEAN __stdcall WxAddFreeHeapChunk(WX_HEAP*, WX_HEAP_EXTENT*, SIZE_T, BOOLEAN);
WX_HEAP_CHUNK_HEADER* __stdcall WxCoalesceFreeHeapChunks(WX_HEAP_CHUNK_HEADER*);

// Hlpers
BOOLEAN __stdcall ExtractDefaultHeapSizes(SIZE_T*, SIZE_T*);
BOOLEAN __stdcall IsBadPointer(LPVOID);
INT __stdcall GetListIndex(SIZE_T);

// =============================================================

SIZE_T default_heap_reserve = 0x0, default_heap_commit = 0x0;
DWORD __tls_index = TLS_OUT_OF_INDEXES;
HANDLE default_wx_heap = 0x0;
BOOLEAN b_terminate_on_corruption = 0x0;

// ============================================================

BOOL __stdcall DllMain(HMODULE dll_base, DWORD call_reason, LPVOID unused) {
	UNREFERENCED_PARAMETER(unused);
	if (call_reason == DLL_PROCESS_ATTACH) {
		__tls_index = TlsAlloc();
		if (__tls_index == TLS_OUT_OF_INDEXES) return 0x0;

		if (!ExtractDefaultHeapSizes(&default_heap_reserve, &default_heap_commit)) return 0x0;

		TlsSetValue(__tls_index, &default_wx_heap);
	}
	else if (call_reason == DLL_PROCESS_DETACH) {
		TlsSetValue(__tls_index, 0x0);
		if (__tls_index != TLS_OUT_OF_INDEXES) TlsFree(__tls_index);
	}
	else if (call_reason == DLL_THREAD_ATTACH) TlsSetValue(__tls_index, &default_wx_heap);
	else if (call_reason == DLL_THREAD_DETACH) TlsSetValue(__tls_index, 0x0);
	else return 0x0;

	return 0x1;
}

// ============================================================

BOOLEAN __stdcall WxHeapManagerInit() {
	if (!default_heap_reserve || !default_heap_commit) return 0x0;
	default_wx_heap = WxCreateHeap(WX_HEAP_FLAG_GROWABLE | WX_HEAP_FLAG_SUPPORT_COALESCING | WX_HEAP_FLAG_SUPPORT_FRAGMENTATION, default_heap_reserve,
		default_heap_commit);
	return default_wx_heap ? 0x1 : 0x0;
}

void __stdcall WxInitializeListHead(PWX_LIST_ENTRY list_head) {
	if (!list_head) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	list_head->Flink = list_head->Blink = list_head;
}

void __stdcall WxInsertHeadList(PWX_LIST_ENTRY list_head, PWX_LIST_ENTRY new_entry) {
	if (!list_head || !new_entry || !list_head->Blink || !list_head->Flink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	new_entry->Flink = list_head;
	new_entry->Blink = list_head->Blink;
	list_head->Blink->Flink = new_entry;
	list_head->Blink = new_entry;
}

void __stdcall WxRemoveFromList(PWX_LIST_ENTRY entry_to_remove) {
	if (!entry_to_remove || !entry_to_remove->Flink || !entry_to_remove->Blink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	entry_to_remove->Blink->Flink = entry_to_remove->Flink;
	entry_to_remove->Flink->Blink = entry_to_remove->Blink;

	entry_to_remove->Flink = entry_to_remove->Blink = 0x0;
}

void __stdcall WxRemoveInsertHeadList(PWX_LIST_ENTRY list_head, PWX_LIST_ENTRY entry) {
	if (!list_head || !entry || !list_head->Blink || !list_head->Flink || !entry->Flink || !entry->Blink) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	entry->Blink->Flink = entry->Flink;
	entry->Flink->Blink = entry->Blink;

	entry->Flink = list_head;
	entry->Blink = list_head->Blink;
	list_head->Blink->Flink = entry;
	list_head->Blink = entry;
}

BOOLEAN __stdcall ExtractDefaultHeapSizes(SIZE_T* reserved_size, SIZE_T* commited_size) {
	if (IsBadPointer(reserved_size) || IsBadPointer(commited_size)) {
		SetLastError(87);
		return 0x0;
	}

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)GetModuleHandleW((LPCWSTR)0x0);
	if (!dos_hdr) return 0x0;

	IMAGE_NT_HEADERS* nt_hdr = (IMAGE_NT_HEADERS*)((UINT_PTR)dos_hdr + dos_hdr->e_lfanew);

	SYSTEM_INFO system_info = { 0x0 };
	GetSystemInfo(&system_info);

	*reserved_size = nt_hdr->OptionalHeader.SizeOfHeapReserve ? nt_hdr->OptionalHeader.SizeOfHeapReserve : system_info.dwAllocationGranularity;
	*commited_size = nt_hdr->OptionalHeader.SizeOfHeapCommit ? nt_hdr->OptionalHeader.SizeOfHeapCommit : system_info.dwPageSize;

	return 0x1;
}

BOOLEAN __stdcall IsBadPointer(LPVOID pointer) {
	if (!pointer) return 0x1;
	__try {
		*(LPBYTE*)pointer = *(LPBYTE*)pointer;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return 0x1;
	}
	return 0x0;
}

HANDLE __stdcall WxCreateHeap(DWORD flags, SIZE_T reserved_size, SIZE_T commited_size) {
	reserved_size = reserved_size ? reserved_size : default_heap_reserve;
	commited_size = commited_size ? commited_size : default_heap_commit;

	if (commited_size > reserved_size) {
		SIZE_T buffer = reserved_size;
		reserved_size = commited_size;
		commited_size = buffer;
	}

	SYSTEM_INFO system_info = { 0x0 };
	GetSystemInfo(&system_info);

	commited_size = commited_size <= system_info.dwPageSize ? commited_size : system_info.dwPageSize;

	LPBYTE extent = (LPBYTE)VirtualAlloc(0x0, reserved_size, MEM_RESERVE, (flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ? PAGE_EXECUTE_READWRITE :
		PAGE_READWRITE);
	if (!extent) return 0x0;

	HANDLE heap = 0x0;

	extent = (LPBYTE)VirtualAlloc(extent, commited_size, MEM_COMMIT, (flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ? PAGE_EXECUTE_READWRITE :
		PAGE_READWRITE);
	if (!extent) goto FREE_EXTENT;
	else {
		WX_HEAP* heap_info = (WX_HEAP*)extent;
		heap_info->flags = (flags & (WX_HEAP_FLAG_VALID_MASK)); // keep only valid flags
		heap_info->extents_count = 0x1;
		heap_info->signature = 0xDDDD;

		InitializeCriticalSection(&heap_info->sync_object);

		WxInitializeListHead(&heap_info->extents_list_head);
		WxInitializeListHead(&heap_info->large_allocations);

		WX_HEAP_EXTENT* extent_info = (WX_HEAP_EXTENT*)((UINT_PTR)extent + sizeof WX_HEAP);
		if (!WxInitializeHeapExtent(extent_info, extent, reserved_size, commited_size)) goto CLOSE_HEAP_EVENT;
		else {
			extent_info->current_offset += sizeof WX_HEAP;

			WxInsertHeadList(&heap_info->extents_list_head, &extent_info->list_entry);

			heap_info->frontend_allocator = (WX_HEAP_FRONTEND*)((UINT_PTR)extent_info->base_address + extent_info->current_offset);
			if (!WxInitializeHeapFrontend(heap_info->frontend_allocator)) goto CLOSE_HEAP_EVENT;
			else {
				extent_info->current_offset += sizeof _WX_HEAP_FRONTEND;

				//for(UINT i = 0x0; i < WX_HEAP_INITIAL_FREE_CHUNKS; i++) WxAddFreeHeapChunk(heap_info, extent_info, 0xC, 0x0);

				extent_info->current_offset = (extent_info->current_offset + 0xF) & ~0xF;

				heap = (HANDLE)heap_info;
				goto EPILOGUE;
			}
		}
	CLOSE_HEAP_EVENT:
		DeleteCriticalSection(&heap_info->sync_object);
	}

FREE_EXTENT:
	VirtualFree(extent, 0x0, MEM_RELEASE);
EPILOGUE:
	return heap;
}

BOOLEAN __stdcall WxInitializeHeapExtent(WX_HEAP_EXTENT* extent_info, LPBYTE base_address, SIZE_T total_size, SIZE_T commited_size) {
	if (IsBadPointer(extent_info) || IsBadPointer(base_address) || !total_size || !commited_size) {
		SetLastError(87);
		return 0x0;
	}

	if (commited_size > total_size) {
		SIZE_T buffer = commited_size;
		commited_size = total_size;
		total_size = buffer;
	}

	extent_info->base_address = base_address;
	extent_info->total_size = total_size;
	extent_info->commited_size = commited_size;
	extent_info->current_offset = sizeof WX_HEAP_EXTENT;
	extent_info->signature = 0xDDDD;
	extent_info->list_entry.Flink = extent_info->list_entry.Blink = 0x0;

	WxInitializeListHead(&extent_info->busy_chunks_list_head);
	WxInitializeListHead(&extent_info->free_chunks_list_head);
	WxInitializeListHead(&extent_info->coalescing_helper_list_head);

	return 0x1;
}

BOOLEAN __stdcall WxInitializeHeapChunk(WX_HEAP_CHUNK_HEADER* heap_chunk, WX_LIST_ENTRY* extent_list_entry, DWORD flags, SIZE_T total_size) {
	if (IsBadPointer(heap_chunk) || !total_size || IsBadPointer(extent_list_entry)) {
		SetLastError(87);
		return 0x0;
	}

	heap_chunk->signature = 0xDDDD;
	heap_chunk->flags = flags;
	heap_chunk->total_size = total_size;
	heap_chunk->extent_list_entry = extent_list_entry;
	heap_chunk->coalescing_list_entry.Flink = heap_chunk->coalescing_list_entry.Blink = 0x0;
	heap_chunk->list_entry.Flink = heap_chunk->list_entry.Blink = 0x0;

	return 0x1;
}

LPVOID __stdcall WxHeapAlloc(HANDLE wx_heap, DWORD flags, SIZE_T allocation_size) {
	if (IsBadPointer(wx_heap) || !allocation_size) {
		SetLastError(87);
		return 0x0;
	}

	WX_HEAP* heap_info = (WX_HEAP*)wx_heap;
	if (heap_info->signature != 0xDDDD) {
		SetLastError(87);
		return 0x0;
	}

	if (!(heap_info->flags & WX_HEAP_FLAG_NO_SERIALIZE)) EnterCriticalSection(&heap_info->sync_object);

	SYSTEM_INFO system_info = { 0x0 };
	GetSystemInfo(&system_info);

	BOOLEAN b_large_allocation = allocation_size >= system_info.dwPageSize ? 0x1 : 0x0;

	if (!b_large_allocation && heap_info->frontend_allocator) {
		LPBYTE chunk_body = 0x0;

		INT index = GetListIndex(allocation_size);
		if (index != 0xffffffff) {
			WX_LIST_ENTRY* free_chunk = heap_info->frontend_allocator->free_chunks[index].Flink;
			if (free_chunk == &heap_info->frontend_allocator->free_chunks[index]) goto FAST_ALLOCATION_END;
			else {
				WX_HEAP_CHUNK_HEADER* chunk_hdr = CONTAINING_RECORD(free_chunk, WX_HEAP_CHUNK_HEADER, frontend_list_entry);
				if (IsBadPointer(chunk_hdr) || IsBadPointer(chunk_hdr->extent_list_entry)) goto FAST_ALLOCATION_END;
				else {
					WX_HEAP_EXTENT* extent = CONTAINING_RECORD(chunk_hdr->extent_list_entry, WX_HEAP_EXTENT, list_entry);
					if (IsBadPointer(extent)) goto FAST_ALLOCATION_END;
					else {
						WxRemoveInsertHeadList(&extent->busy_chunks_list_head, &chunk_hdr->list_entry);
						WxRemoveFromList(free_chunk);

						chunk_body = (LPBYTE)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER;
					}
				}
			}
		}

	FAST_ALLOCATION_END:
		if (chunk_body) {
			LeaveCriticalSection(&heap_info->sync_object);
			return chunk_body;
		}
	}

	if (!heap_info->extents_count) {
		LeaveCriticalSection(&heap_info->sync_object);
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	WX_LIST_ENTRY* extent_iterator = heap_info->extents_list_head.Flink;
	WX_LIST_ENTRY* extent_list_head = &heap_info->extents_list_head;

	LPBYTE chunk_body = 0x0;

	WX_HEAP_EXTENT* extent_info = 0x0;
	SIZE_T charged_quota = 0x0, required_size = b_large_allocation ? (sizeof WX_HEAP_LARGE_ALLOCATION + sizeof WX_HEAP_CHUNK_HEADER) :
		(allocation_size + sizeof WX_HEAP_CHUNK_HEADER);

	while (extent_iterator != extent_list_head) {
		extent_info = CONTAINING_RECORD(extent_iterator, WX_HEAP_EXTENT, list_entry);

		if (!IsBadPointer(extent_info)) {
		ALLOCATE_NEW_CHUNK:
			extent_info = CONTAINING_RECORD(extent_iterator, WX_HEAP_EXTENT, list_entry);
			if (!IsBadPointer(extent_info)) {

				WX_LIST_ENTRY* chunk_iterator = extent_info->free_chunks_list_head.Flink;
				WX_LIST_ENTRY* free_chunk_list_head = &extent_info->free_chunks_list_head;

				while (chunk_iterator != free_chunk_list_head) {
					WX_HEAP_CHUNK_HEADER* chunk_hdr = CONTAINING_RECORD(chunk_iterator, WX_HEAP_CHUNK_HEADER, list_entry);
					if (!IsBadPointer(chunk_hdr)) {
						if (!b_large_allocation) {
							if (chunk_hdr->total_size >= required_size) break;
						}
						else {
							if (chunk_hdr->flags & WX_HEAP_FLAG_LARGE_ALLOCATION) {
								WX_HEAP_LARGE_ALLOCATION* large_alloc_info = (WX_HEAP_LARGE_ALLOCATION*)((UINT_PTR)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER);
								if (!IsBadPointer(large_alloc_info)) break;
							}
							else {
								if (chunk_hdr->total_size >= required_size) break;
							}
						}
					}
					chunk_iterator = chunk_iterator->Flink;
				}

				if (chunk_iterator == free_chunk_list_head) {
					// there is no free suitable chunk
					if ((extent_info->total_size - extent_info->current_offset) >= required_size) {
						if ((extent_info->current_offset + required_size) > extent_info->commited_size) WxCommitHeapExtent(extent_info, 0x0, 0x0);
						WX_HEAP_CHUNK_HEADER* chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)extent_info->base_address + extent_info->current_offset);
						if (!IsBadPointer(chunk_hdr)) {
							if (WxInitializeHeapChunk(chunk_hdr, &extent_info->list_entry, b_large_allocation ? WX_HEAP_FLAG_LARGE_ALLOCATION : 0x0, required_size)) {
								WxInsertHeadList(&extent_info->busy_chunks_list_head, &chunk_hdr->list_entry);
								if (heap_info->flags & WX_HEAP_FLAG_SUPPORT_COALESCING)
									WxInsertHeadList(&extent_info->coalescing_helper_list_head, &chunk_hdr->coalescing_list_entry);
								if (!b_large_allocation) chunk_body = (LPBYTE)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER;
								else {
									chunk_body = (LPBYTE)VirtualAlloc(0x0, allocation_size, MEM_RESERVE | MEM_COMMIT, (heap_info->flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ?
										PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
									if (chunk_body) {
										WX_HEAP_LARGE_ALLOCATION* large_alloc_info = (WX_HEAP_LARGE_ALLOCATION*)((UINT_PTR)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER);
										large_alloc_info->address = chunk_body;
										large_alloc_info->size = allocation_size;
										WxInsertHeadList(&heap_info->large_allocations, &large_alloc_info->list_entry);
									}
									else {
										WxRemoveFromList(&chunk_hdr->list_entry);
										goto OUT_OF_MEMORY;
									}
								}
								charged_quota = chunk_hdr->total_size;
								goto EPILOGUE_0;
							}
						}
						goto OUT_OF_MEMORY;
					}
					else goto CREATE_NEW_EXTENT;
				}
				else {
					// reserve the ree chunk
					WX_HEAP_CHUNK_HEADER* chunk_hdr = CONTAINING_RECORD(chunk_iterator, WX_HEAP_CHUNK_HEADER, list_entry);

					if (chunk_hdr->flags != WX_HEAP_FLAG_FREE_CHUNK) goto EPILOGUE;

					else {
						WxRemoveInsertHeadList(&extent_info->busy_chunks_list_head, chunk_iterator);
						WxRemoveFromList(&chunk_hdr->frontend_list_entry);

						SIZE_T previous_size = 0x0, unused_space = 0x0;

						if (!b_large_allocation) {
							chunk_body = (LPBYTE)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER;
							previous_size = chunk_hdr->total_size - sizeof WX_HEAP_CHUNK_HEADER;
							unused_space = previous_size - allocation_size;
						}
						else {
							WX_HEAP_LARGE_ALLOCATION* large_alloc_info = (WX_HEAP_LARGE_ALLOCATION*)((UINT_PTR)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER);
							if (chunk_hdr->flags & WX_HEAP_FLAG_LARGE_ALLOCATION) {
								if (large_alloc_info->size >= allocation_size) {
									previous_size = large_alloc_info->size;
									large_alloc_info->size = allocation_size;
									chunk_body = (LPBYTE)large_alloc_info->address;
									goto ZERO_MEMMORY;
								}
								else {
									WxRemoveFromList(&large_alloc_info->list_entry);
									VirtualFree(large_alloc_info->address, 0x0, MEM_RELEASE);
								}
							}
							chunk_body = (LPBYTE)VirtualAlloc(0x0, allocation_size, MEM_RESERVE | MEM_COMMIT, (heap_info->flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ?
								PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
							if (chunk_body) {
								large_alloc_info->address = chunk_body;
								large_alloc_info->size = allocation_size;
								WxInsertHeadList(&heap_info->large_allocations, &large_alloc_info->list_entry);

								SIZE_T header_size = sizeof WX_HEAP_CHUNK_HEADER + sizeof WX_HEAP_LARGE_ALLOCATION;
								unused_space = chunk_hdr->total_size - header_size;
								WxZeroMemory((LPBYTE)chunk_hdr + header_size, unused_space);
							}
							else goto OUT_OF_MEMORY;
						}

					ZERO_MEMMORY:
						chunk_hdr->flags = b_large_allocation ? WX_HEAP_FLAG_LARGE_ALLOCATION : 0x0;
						if ((flags & WX_HEAP_FLAG_ZERO_MEMORY) && previous_size) WxZeroMemory(chunk_body, previous_size);

						if ((heap_info->flags & WX_HEAP_FLAG_SUPPORT_FRAGMENTATION) && unused_space > sizeof WX_HEAP_CHUNK_HEADER) {
							chunk_hdr->total_size -= unused_space;
							WX_HEAP_CHUNK_HEADER* new_chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)chunk_hdr + chunk_hdr->total_size);
							if (!IsBadPointer(new_chunk_hdr)) {
								if (WxInitializeHeapChunk(new_chunk_hdr, &extent_info->list_entry, WX_HEAP_FLAG_FREE_CHUNK, unused_space)) {
									WxInsertHeadList(&extent_info->free_chunks_list_head, &new_chunk_hdr->list_entry);
									if (heap_info->frontend_allocator) {
										INT index = GetListIndex(unused_space - sizeof WX_HEAP_CHUNK_HEADER);
										if (index != 0xffffffff || !index) WxInsertHeadList(&heap_info->frontend_allocator->free_chunks[index - 1],
											&new_chunk_hdr->frontend_list_entry);
									}
									// update the coalescing helper list
									if (heap_info->flags & WX_HEAP_FLAG_SUPPORT_COALESCING) {
										new_chunk_hdr->coalescing_list_entry.Flink = chunk_hdr->coalescing_list_entry.Flink;
										new_chunk_hdr->coalescing_list_entry.Blink = &chunk_hdr->coalescing_list_entry;
										chunk_hdr->coalescing_list_entry.Flink = &new_chunk_hdr->coalescing_list_entry;
									}
								}
							}
						}
					}
				}
				goto EPILOGUE_0;
			}
		}
		extent_iterator = extent_iterator->Flink;
	}

	if (extent_iterator == extent_list_head) {
		// all extents are full
	CREATE_NEW_EXTENT:
		if ((heap_info->flags & WX_HEAP_FLAG_GROWABLE)) {
			SYSTEM_INFO system_info = { 0x0 };
			GetSystemInfo(&system_info);

			LPBYTE extent = (LPBYTE)VirtualAlloc(0x0, WX_HEAP_DEFAULT_EXTENT_MAX_SIZE_IN_PAGES * system_info.dwPageSize, MEM_RESERVE,
				(heap_info->flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
			if (!extent) goto OUT_OF_MEMORY;
			else {
				extent = (LPBYTE)VirtualAlloc(0x0, system_info.dwPageSize, MEM_COMMIT, (heap_info->flags & WX_HEAP_FLAG_CREATE_ENABLE_EXECUTE) ?
					PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
				if (!extent) goto FREE_EXTENT;
				else {
					extent_info = (WX_HEAP_EXTENT*)extent;
					if (!WxInitializeHeapExtent(extent_info, extent, WX_HEAP_DEFAULT_EXTENT_MAX_SIZE_IN_PAGES * system_info.dwPageSize,
						system_info.dwPageSize)) goto FREE_EXTENT;
					else {
						//for (UINT i = 0x0; i < WX_HEAP_INITIAL_FREE_CHUNKS; i++) WxAddFreeHeapChunk(heap_info, extent_info, allocation_size, 0x0);
						WxInsertHeadList(&heap_info->extents_list_head, &extent_info->list_entry);
						extent_iterator = &extent_info->list_entry;

						heap_info->extents_count++;

						goto ALLOCATE_NEW_CHUNK;
					}
				}
			FREE_EXTENT:
				VirtualFree(extent, 0x0, MEM_RELEASE);
			}
		}
	OUT_OF_MEMORY:
		LeaveCriticalSection(&heap_info->sync_object);
		SetLastError(ERROR_OUTOFMEMORY);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

EPILOGUE_0:
	extent_info->current_offset += charged_quota;
	extent_info->current_offset = (extent_info->current_offset + 0xF) & ~0xF;

EPILOGUE:
	LeaveCriticalSection(&heap_info->sync_object);

	return chunk_body;
}

BOOLEAN  __stdcall WxHeapFree(HANDLE wx_heap, LPVOID heap_chunk) {
	if (IsBadPointer(wx_heap) || IsBadPointer(heap_chunk)) {
		SetLastError(87);
		return 0x0;
	}

	WX_HEAP* heap_info = (WX_HEAP*)wx_heap;

	if (heap_info->signature != 0xDDDD) {
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	if (!(heap_info->flags & WX_HEAP_FLAG_NO_SERIALIZE)) EnterCriticalSection(&heap_info->sync_object);

	WX_LIST_ENTRY* large_alloc_iterator = heap_info->large_allocations.Flink;
	WX_LIST_ENTRY* large_alloc_list_head = &heap_info->large_allocations;

	WX_HEAP_CHUNK_HEADER* chunk_hdr = 0x0;
	BOOLEAN b_large_allocation = 0x0;

	while (large_alloc_iterator != large_alloc_list_head) {
		WX_HEAP_LARGE_ALLOCATION* large_alloc_info = CONTAINING_RECORD(large_alloc_iterator, WX_HEAP_LARGE_ALLOCATION, list_entry);
		if (!IsBadPointer(large_alloc_info) && large_alloc_info->address == heap_chunk) {
			chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)large_alloc_info - sizeof WX_HEAP_CHUNK_HEADER);
			if (!IsBadPointer(chunk_hdr) && chunk_hdr->flags & WX_HEAP_FLAG_LARGE_ALLOCATION) {
				WxRemoveFromList(&large_alloc_info->list_entry);
				b_large_allocation = 0x1;
				goto FREE_HEAP_CHUNK;
			}
			else {
				LeaveCriticalSection(&heap_info->sync_object);
				SetLastError(87);
				if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
				return 0x0;
			}
		}
		large_alloc_iterator = large_alloc_iterator->Flink;
	}


	if (!heap_info->extents_count) {
		LeaveCriticalSection(&heap_info->sync_object);
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)heap_chunk - sizeof WX_HEAP_CHUNK_HEADER);

FREE_HEAP_CHUNK:

	if (IsBadPointer(chunk_hdr) || chunk_hdr->signature != 0xDDDD || IsBadPointer(chunk_hdr->extent_list_entry)) {
		LeaveCriticalSection(&heap_info->sync_object);
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	WX_HEAP_EXTENT* extent = CONTAINING_RECORD(chunk_hdr->extent_list_entry, WX_HEAP_EXTENT, list_entry);
	if (IsBadPointer(extent) || extent->signature != 0xDDDD) {
		LeaveCriticalSection(&heap_info->sync_object);
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	chunk_hdr->flags |= WX_HEAP_FLAG_FREE_CHUNK;

	if (!b_large_allocation) {
		LPBYTE body = (LPBYTE)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER;
		SIZE_T body_size = chunk_hdr->total_size - sizeof WX_HEAP_CHUNK_HEADER;
		WxZeroMemory(body, body_size);

		if (heap_info->flags & WX_HEAP_FLAG_SUPPORT_COALESCING) {
			chunk_hdr = WxCoalesceFreeHeapChunks(chunk_hdr);
			body_size = chunk_hdr->total_size - sizeof WX_HEAP_CHUNK_HEADER;
		}

		if (heap_info->frontend_allocator) {
			INT index = GetListIndex(body_size);
			if (index != 0xffffffff || !index) WxRemoveInsertHeadList(&heap_info->frontend_allocator->free_chunks[index - 1], &chunk_hdr->frontend_list_entry);
		}
	}

	WxRemoveInsertHeadList(&extent->free_chunks_list_head, &chunk_hdr->list_entry);

	LeaveCriticalSection(&heap_info->sync_object);

	return 0x1;
}

BOOLEAN __stdcall WxDestroyHeap(HANDLE wx_heap) {
	if (IsBadPointer(wx_heap)) {
		SetLastError(87);
		return 0x0;
	}

	WX_HEAP* heap_info = (WX_HEAP*)wx_heap;
	if (heap_info->signature != 0xDDDD) {
		SetLastError(87);
		return 0x0;
	}

	if (!(heap_info->flags & WX_HEAP_FLAG_NO_SERIALIZE)) EnterCriticalSection(&heap_info->sync_object);

	vector<LPVOID> extent_bases, large_allocations;

	WX_LIST_ENTRY* extent_iterator = heap_info->extents_list_head.Flink;
	WX_LIST_ENTRY* extent_list_head = &heap_info->extents_list_head;
	while (extent_iterator != extent_list_head) {
		WX_HEAP_EXTENT* extent_info = CONTAINING_RECORD(extent_iterator, WX_HEAP_EXTENT, list_entry);
		if (!IsBadPointer(extent_info) && extent_info->signature == 0xDDDD) {
			extent_bases.push_back(extent_info->base_address);
		}
		extent_iterator = extent_iterator->Flink;
	}

	WX_LIST_ENTRY* large_alloc_iterator = heap_info->large_allocations.Flink;
	WX_LIST_ENTRY* large_alloc_head = &heap_info->large_allocations;
	while (large_alloc_iterator != large_alloc_head) {
		WX_HEAP_LARGE_ALLOCATION* large_alloc_info = CONTAINING_RECORD(large_alloc_iterator, WX_HEAP_LARGE_ALLOCATION, list_entry);
		if (!IsBadPointer(large_alloc_info) && large_alloc_info->size && large_alloc_info->address) large_allocations.push_back(large_alloc_info->address);
		large_alloc_iterator = large_alloc_iterator->Flink;
	}

	LeaveCriticalSection(&heap_info->sync_object);

	for (UINT i = 0x0; i < extent_bases.size(); i++) if (!IsBadPointer(extent_bases[i])) VirtualFree(extent_bases[i], 0x0, MEM_RELEASE);
	for (UINT i = 0x0; i < large_allocations.size(); i++) if (!IsBadPointer(large_allocations[i])) VirtualFree(large_allocations[i], 0x0, MEM_RELEASE);

	return 0x1;
}

BOOLEAN __stdcall WxCommitHeapExtent(WX_HEAP_EXTENT* heap_extent, SIZE_T commit_size, BOOLEAN b_sync) {
	if (IsBadPointer(heap_extent)) {
		SetLastError(87);
		return 0x0;
	}

	SYSTEM_INFO system_info = { 0x0 };
	GetSystemInfo(&system_info);

	commit_size = commit_size ? commit_size : system_info.dwPageSize;
	commit_size = commit_size <= (heap_extent->total_size - heap_extent->commited_size) ? commit_size : (heap_extent->total_size - heap_extent->commited_size);

	BOOLEAN b_ret = 0x0;

	if (heap_extent->commited_size >= heap_extent->total_size) goto EPILOGUE;

	if (!(LPBYTE)VirtualAlloc((LPVOID)((UINT_PTR)heap_extent->base_address + heap_extent->commited_size), commit_size, MEM_COMMIT,
		(PAGE_READWRITE))) return 0x0;


	heap_extent->commited_size += commit_size;
	b_ret = 0x1;

EPILOGUE:
	return b_ret;

}

LPVOID __stdcall WxHeapReAlloc(HANDLE wx_heap, LPVOID heap_chunk, DWORD flags, SIZE_T allocation_size) {
	if (IsBadPointer(wx_heap) || IsBadPointer(heap_chunk) || !allocation_size) {
		SetLastError(87);
		return 0x0;
	}

	LPVOID new_chunk = 0x0;

	WX_HEAP* heap_info = (WX_HEAP*)wx_heap;
	if (heap_info->signature != 0xDDDD) {
		SetLastError(87);
		if (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
		return 0x0;
	}

	if (!(heap_info->flags & WX_HEAP_FLAG_NO_SERIALIZE)) EnterCriticalSection(&heap_info->sync_object);

	if (!heap_info->extents_count) {
		SetLastError(87);
		new_chunk = 0x0;
		goto SET_HEAP_EVENT;
	}
	else {

		WX_LIST_ENTRY* large_alloc_iterator = heap_info->large_allocations.Flink;
		WX_LIST_ENTRY* large_alloc_list_head = &heap_info->large_allocations;

		WX_HEAP_CHUNK_HEADER* chunk_hdr = 0x0;
		SIZE_T body_size = 0x0;
		LPBYTE body = 0x0;

		while (large_alloc_iterator != large_alloc_list_head) {
			WX_HEAP_LARGE_ALLOCATION* large_alloc_info = CONTAINING_RECORD(large_alloc_iterator, WX_HEAP_LARGE_ALLOCATION, list_entry);
			if (!IsBadPointer(large_alloc_info) && large_alloc_info->address == heap_chunk) {
				chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)large_alloc_info - sizeof WX_HEAP_CHUNK_HEADER);
				body_size = large_alloc_info->size;
				body = (LPBYTE)heap_chunk;
				if (!IsBadPointer(chunk_hdr) && chunk_hdr->flags & WX_HEAP_FLAG_LARGE_ALLOCATION) goto WX_HEAP_REALLOC;
				else {
					LeaveCriticalSection(&heap_info->sync_object);
					SetLastError(87);
					return 0x0;
				}
			}
			large_alloc_iterator = large_alloc_iterator->Flink;
		}

		chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)heap_chunk - sizeof WX_HEAP_CHUNK_HEADER);
		body_size = chunk_hdr->total_size - sizeof WX_HEAP_CHUNK_HEADER;
		body = (LPBYTE)chunk_hdr + sizeof WX_HEAP_CHUNK_HEADER;

	WX_HEAP_REALLOC:
		if (IsBadPointer(chunk_hdr) || chunk_hdr->signature != 0xDDDD || IsBadPointer(chunk_hdr->extent_list_entry) || !body_size || !body) {
			SetLastError(87);
			new_chunk = 0x0;
			goto SET_HEAP_EVENT;
		}
		else {
			if (body_size >= allocation_size) {
				new_chunk = heap_chunk;
				if (flags & WX_HEAP_FLAG_ZERO_MEMORY) WxZeroMemory(body + allocation_size, body_size - allocation_size);
				goto SET_HEAP_EVENT;
			}
			else {
				LeaveCriticalSection(&heap_info->sync_object);

				LPBYTE heap_chunk_0 = (LPBYTE)WxHeapAlloc(wx_heap, flags, allocation_size);
				if (!heap_chunk_0) new_chunk = 0x0;
				else {
					CopyMemory(heap_chunk_0, heap_chunk, body_size);
					WxHeapFree(wx_heap, heap_chunk);
					new_chunk = heap_chunk_0;
				}
				goto EPILOGUE;
			}
		}
	}

SET_HEAP_EVENT:
	LeaveCriticalSection(&heap_info->sync_object);

EPILOGUE:
	if (!new_chunk && (heap_info->flags & WX_HEAP_FLAG_GENERATE_EXCEPTIONS)) RaiseException(EXCEPTION_SOFTWARE_ORIGINATE, EXCEPTION_NONCONTINUABLE, 0x0, 0x0);
	return new_chunk;
}

BOOLEAN __stdcall WxInitializeHeapFrontend(WX_HEAP_FRONTEND* frontend_allocator) {
	if (IsBadPointer(frontend_allocator)) {
		SetLastError(87);
		return 0x0;
	}

	frontend_allocator->signature = 0xDDDD;
	for (UINT i = 0x0; i < 0xA; i++) WxInitializeListHead(&frontend_allocator->free_chunks[i]);

	return 0x1;
}

INT __stdcall GetListIndex(SIZE_T allocation_size) {
	if (!allocation_size) {
		SetLastError(87);
		return 0xFFFFFFFF;
	}

	SIZE_T sizes[0xa] = { 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400 };
	INT index = 0xFFFFFFFF;
	for (INT i = 0x9; i >= 0x0; i--) if (allocation_size >= sizes[i]) {
		index = i;
		break;
	}

	return index;
}

BOOLEAN __stdcall WxAddFreeHeapChunk(WX_HEAP* wx_heap, WX_HEAP_EXTENT* extent, SIZE_T chunk_body_size, BOOLEAN b_sync) {
	if (IsBadPointer(wx_heap) || IsBadPointer(extent) || !chunk_body_size) {
		SetLastError(87);
		return 0x0;
	}

	SYSTEM_INFO system_info = { 0x0 };
	GetSystemInfo(&system_info);

	BOOLEAN b_ret = 0x0;
	if (chunk_body_size >= system_info.dwPageSize) goto EPILOGUE;
	else {

		if ((extent->total_size - extent->current_offset) < (chunk_body_size + sizeof WX_HEAP_CHUNK_HEADER)) goto UNLOCK_EXTENT;
		else {
			WX_HEAP_CHUNK_HEADER* chunk_hdr = (WX_HEAP_CHUNK_HEADER*)((UINT_PTR)extent->base_address + extent->current_offset);
			if (IsBadPointer(chunk_hdr)) goto UNLOCK_EXTENT;
			else {
				if (!WxInitializeHeapChunk(chunk_hdr, &extent->list_entry, 0x0, chunk_body_size + sizeof WX_HEAP_CHUNK_HEADER)) goto UNLOCK_EXTENT;
				else {
					chunk_hdr->flags = WX_HEAP_FLAG_FREE_CHUNK;
					WxInsertHeadList(&extent->free_chunks_list_head, &chunk_hdr->list_entry);
					WxInsertHeadList(&extent->coalescing_helper_list_head, &chunk_hdr->coalescing_list_entry);

					INT index = GetListIndex(chunk_body_size);
					if (index != 0xFFFFFFFF) WxInsertHeadList(&wx_heap->frontend_allocator->free_chunks[index], &chunk_hdr->frontend_list_entry);
					extent->current_offset += (chunk_body_size + sizeof WX_HEAP_CHUNK_HEADER);
					extent->current_offset = (extent->current_offset + 0xF) & ~0xF;

					b_ret = 0x1;
				}
			}
		}
	UNLOCK_EXTENT:
		if (b_ret && extent->current_offset >= extent->commited_size) WxCommitHeapExtent(extent, 0x0, 0x0);
	}

EPILOGUE:
	return b_ret;
}

HANDLE __stdcall GetProcessWxHeap() {
	HANDLE* wx_heap = (HANDLE*)TlsGetValue(__tls_index);
	if (IsBadPointer(wx_heap)) return 0x0;
	return *wx_heap;
}

WX_HEAP_CHUNK_HEADER* __stdcall WxCoalesceFreeHeapChunks(WX_HEAP_CHUNK_HEADER* chunk_hdr) {
	if (IsBadPointer(chunk_hdr) || !chunk_hdr->coalescing_list_entry.Flink || !chunk_hdr->coalescing_list_entry.Blink || IsBadPointer(chunk_hdr->extent_list_entry)) {
		SetLastError(87);
		return chunk_hdr;
	}

	if (!(chunk_hdr->flags & WX_HEAP_FLAG_FREE_CHUNK)) {
		SetLastError(87);
		return chunk_hdr;
	}

	WX_HEAP_EXTENT* extent = CONTAINING_RECORD(chunk_hdr->extent_list_entry, WX_HEAP_EXTENT, list_entry);
	if (IsBadPointer(extent)) {
		SetLastError(87);
		return chunk_hdr;
	}

	SIZE_T total_size = 0x0;
	WX_HEAP_CHUNK_HEADER* merged_chunk = chunk_hdr, * next_chunk = 0x0, * pre_chunk = 0x0;

	if (chunk_hdr->coalescing_list_entry.Flink != &extent->coalescing_helper_list_head) {
		next_chunk = CONTAINING_RECORD(chunk_hdr->coalescing_list_entry.Flink, WX_HEAP_CHUNK_HEADER, coalescing_list_entry);
		if (!IsBadPointer(next_chunk) && (next_chunk->flags & (WX_HEAP_FLAG_FREE_CHUNK | ~WX_HEAP_FLAG_LARGE_ALLOCATION))) {
			total_size = (SIZE_T)((UINT_PTR)next_chunk - (UINT_PTR)chunk_hdr) + next_chunk->total_size;
		}
	}

	if (chunk_hdr->coalescing_list_entry.Blink != &extent->coalescing_helper_list_head) {
		pre_chunk = CONTAINING_RECORD(chunk_hdr->coalescing_list_entry.Blink, WX_HEAP_CHUNK_HEADER, coalescing_list_entry);
		if (!IsBadPointer(pre_chunk) && (pre_chunk->flags & (WX_HEAP_FLAG_FREE_CHUNK | ~WX_HEAP_FLAG_LARGE_ALLOCATION))) {
			merged_chunk = pre_chunk;
			if (total_size) total_size += (SIZE_T)((UINT_PTR)chunk_hdr - (UINT_PTR)pre_chunk);
			else total_size = (SIZE_T)((UINT_PTR)chunk_hdr - (UINT_PTR)pre_chunk) + chunk_hdr->total_size;
		}
	}
	if (!total_size && merged_chunk == chunk_hdr) goto EPILOGUE;
	else {
		if (next_chunk) {
			WxRemoveFromList(&next_chunk->coalescing_list_entry);
			WxRemoveFromList(&next_chunk->list_entry);
			WxRemoveFromList(&next_chunk->frontend_list_entry);
		}
		if (merged_chunk != chunk_hdr && merged_chunk == pre_chunk) {
			WxRemoveFromList(&chunk_hdr->coalescing_list_entry);
			WxRemoveFromList(&chunk_hdr->list_entry);
			WxRemoveFromList(&chunk_hdr->frontend_list_entry);

		}
		merged_chunk->total_size = total_size;
		merged_chunk->flags = WX_HEAP_FLAG_FREE_CHUNK;
		WxZeroMemory((LPBYTE)merged_chunk + sizeof WX_HEAP_CHUNK_HEADER, total_size - sizeof WX_HEAP_CHUNK_HEADER);
	}

EPILOGUE:
	return merged_chunk;
}

BOOL __stdcall WxHeapSetInformation(HANDLE wx_heap, WX_HEAP_INFORMATION_CLASS info_class, LPVOID info_buffer, SIZE_T buffer_size) {
	if (IsBadPointer(wx_heap)) {
		SetLastError(87);
		return 0x0;
	}

	WX_HEAP* heap_info = (WX_HEAP*)wx_heap;
	if (heap_info->signature != 0xDDDD) {
		SetLastError(87);
		return 0x0;
	}

	if (!(heap_info->flags & WX_HEAP_FLAG_NO_SERIALIZE)) EnterCriticalSection(&heap_info->sync_object);

	if (info_class == WxHeapEnableCoalescing) heap_info->flags |= WX_HEAP_FLAG_SUPPORT_COALESCING;
	else if (info_class == WxHeapEnableFragmentation) heap_info->flags |= WX_HEAP_FLAG_SUPPORT_FRAGMENTATION;
	else if (info_class == WxHeapEnableTerminationOnCorruption) b_terminate_on_corruption = 0x1;

	LeaveCriticalSection(&heap_info->sync_object);
	return 0x1;
}