#ifndef ANTI_HOOK_HPP
#define ANTI_HOOK_HPP

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <ntstatus.h>

typedef enum err_code
{
	err_success,
	err_enum_process_modules_failed,
	err_size_too_small,
	err_mod_name_not_found,
	err_mod_query_failed,
	err_create_file_failed,
	err_create_file_mapping_failed,
	err_create_file_mapping_already_exists,
	err_map_file_failed,
	err_mem_deprotect_failed,
	err_mem_reprotect_failed,
	err_text_section_not_found,
	err_file_path_query_failed
} err_code;

typedef enum suspend_resume_type
{
	srt_suspend,
	srt_resume
} suspend_resume_type, *psuspend_resume_type;

typedef struct suspend_resume_info
{
	ULONG current_pid;
	ULONG current_tid;
	suspend_resume_type type;
} suspend_resume_info, *psuspend_resume_info;

typedef struct wrk_system_process_information
{
	ULONG next_entry_offset;
	ULONG number_of_threads;
	LARGE_INTEGER spare_li1;
	LARGE_INTEGER spare_li2;
	LARGE_INTEGER spare_li3;
	LARGE_INTEGER create_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER kernel_time;
	UNICODE_STRING image_name;
	KPRIORITY base_priority;
	HANDLE unique_process_id;
	HANDLE inherited_from_unique_process_id;
	ULONG handle_count;
	ULONG session_id;
	ULONG_PTR page_directory_base;
	SIZE_T peak_virtual_size;
	SIZE_T virtual_size;
	ULONG page_fault_count;
	SIZE_T peak_working_set_size;
	SIZE_T working_set_size;
	SIZE_T quota_peak_paged_pool_usage;
	SIZE_T quota_paged_pool_usage;
	SIZE_T quota_peak_non_paged_pool_usage;
	SIZE_T quota_non_paged_pool_usage;
	SIZE_T pagefile_usage;
	SIZE_T peak_pagefile_usage;
	SIZE_T private_page_count;
	LARGE_INTEGER read_operation_count;
	LARGE_INTEGER write_operation_count;
	LARGE_INTEGER other_operation_count;
	LARGE_INTEGER read_transfer_count;
	LARGE_INTEGER write_transfer_count;
	LARGE_INTEGER other_transfer_count;
	SYSTEM_THREAD_INFORMATION threads[1];
} wrk_system_process_information, *pwrk_system_process_information;

typedef enum wrk_memory_information_class
{
	memory_basic_information
} wrk_memory_information_class, *pwrk_memory_information_class;

extern "C" NTSTATUS NtFlushInstructionCache(HANDLE, PVOID, SIZE_T);
extern "C" NTSTATUS NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
extern "C" NTSTATUS NtSuspendThread(HANDLE, PULONG);
extern "C" NTSTATUS NtResumeThread(HANDLE, PULONG);
extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
extern "C" NTSTATUS NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);

inline void* teb()
{
#ifdef _AMD64_
	return reinterpret_cast<void*>(__readgsqword(0x30));
#else
	return reinterpret_cast<void*>(__readfsdword(0x18));
#endif
}

inline unsigned int pid()
{
#ifdef _AMD64_
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x40);
#else
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x20);
#endif
}

inline unsigned int tid()
{
#ifdef _AMD64_
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x48);
#else
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x24);
#endif
}

inline PVOID alloc(OPTIONAL PVOID base, SIZE_T size, const ULONG protect)
{
	const auto status = NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &base, base ? 12 : 0, &size,
	                                            MEM_RESERVE | MEM_COMMIT, protect);
	return NT_SUCCESS(status) ? base : nullptr;
}

inline VOID ah_free(PVOID base)
{
	SIZE_T region_size = 0;
	NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &base, &region_size, MEM_RELEASE);
}

inline BOOLEAN NTAPI enum_processes(BOOLEAN (*callback)(pwrk_system_process_information process, PVOID argument),
                                    PVOID arg)
{
	ULONG length = 0;

	auto status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &length);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE;
	}

	auto info = static_cast<pwrk_system_process_information>(alloc(nullptr, length, PAGE_READWRITE));

	if (!info)
	{
		return FALSE;
	}

	status = NtQuerySystemInformation(SystemProcessInformation, info, length, &length);

	if (!NT_SUCCESS(status))
	{
		ah_free(info);
		return FALSE;
	}
	do
	{
		if (!callback(info, arg))
		{
			break;
		}
		info = reinterpret_cast<pwrk_system_process_information>(reinterpret_cast<PBYTE>(info) + info->next_entry_offset
		);
	}
	while (info->next_entry_offset);

	ah_free(info);

	return TRUE;
}

inline BOOLEAN suspend_resume_callback(pwrk_system_process_information process, PVOID argument)
{
	if (!process || !argument)
	{
		return FALSE;
	}

	const auto info = static_cast<psuspend_resume_info>(argument);

	if (reinterpret_cast<SIZE_T>(process->unique_process_id) != static_cast<SIZE_T>(info->current_pid))
	{
		return TRUE;
	}

	for (unsigned int i = 0; i < process->number_of_threads; ++i)
	{
		if (reinterpret_cast<SIZE_T>(process->threads[i].ClientId.UniqueThread) == static_cast<SIZE_T>(info->current_tid
			)
		)
		{
			continue;
		}

		HANDLE h_thread = nullptr;

		const auto status = NtOpenThread(&h_thread, THREAD_SUSPEND_RESUME, nullptr, &process->threads[i].ClientId);

		if (NT_SUCCESS(status) && h_thread)
		{
			ULONG suspend_count = 0;

			switch (info->type)
			{
			case srt_suspend:
				NtSuspendThread(h_thread, &suspend_count);
				break;

			case srt_resume:
				NtResumeThread(h_thread, &suspend_count);
				break;
			}

			NtClose(h_thread);
		}
	}

	return FALSE;
}

inline BOOLEAN suspend_threads()
{
	suspend_resume_info info;
	info.current_pid = pid();
	info.current_tid = tid();
	info.type = srt_suspend;

	return enum_processes(suspend_resume_callback, &info);
}

inline BOOLEAN resume_threads()
{
	suspend_resume_info info;
	info.current_pid = pid();
	info.current_tid = tid();
	info.type = srt_resume;

	return enum_processes(suspend_resume_callback, &info);
}

inline DWORD get_module_name(const HMODULE module, LPSTR module_name, const DWORD size)
{
	const auto length = GetModuleFileNameExA(GetCurrentProcess(), module, module_name, size);
	if (length == 0)
	{
		strncpy(module_name, "<not found>", size - 1);
		return err_mod_name_not_found;
	}

	return err_success;
}

inline DWORD protect_memory(LPVOID address, const SIZE_T size, const DWORD new_protect)
{
	DWORD old_protect = 0;

	const auto b_ret = VirtualProtect(address, size, new_protect, &old_protect);

	if (b_ret == FALSE)
	{
		return 0;
	}

	return old_protect;
}

inline DWORD replace_exec_section(const HMODULE module, LPVOID mapping)
{
	const auto image_dos_header = static_cast<PIMAGE_DOS_HEADER>(mapping);

	const auto image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(mapping) +
		image_dos_header->e_lfanew);

	for (WORD i = 0; i < image_nt_headers->FileHeader.NumberOfSections; i++)
	{
		const auto image_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD_PTR>(
			IMAGE_FIRST_SECTION(image_nt_headers)) + static_cast<DWORD_PTR>(IMAGE_SIZEOF_SECTION_HEADER) * i);
		if (!strcmp(reinterpret_cast<const char*>(image_section_header->Name), ".text"))
		{
			auto protect = protect_memory(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->
					VirtualAddress)), image_section_header->Misc.VirtualSize, PAGE_EXECUTE_READWRITE);

			if (!protect)
			{
				return err_mem_deprotect_failed;
			}

			memcpy(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)),
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(mapping) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)), image_section_header->Misc.VirtualSize);

			protect = protect_memory(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)), image_section_header->Misc.VirtualSize, protect);

			if (!protect)
			{
				return err_mem_reprotect_failed;
			}

			return err_success;
		}
	}
	return err_text_section_not_found;
}

inline DWORD unhook_module(const HMODULE module)
{
	CHAR module_name[MAX_PATH];

	ZeroMemory(module_name, sizeof module_name);

	auto ret = get_module_name(module, module_name, sizeof module_name);
	if (ret == err_mod_name_not_found)
	{
		return ret;
	}

	const auto file = CreateFileA(module_name, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		return err_create_file_failed;
	}

	const auto file_mapping = CreateFileMapping(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
	if (!file_mapping)
	{
		CloseHandle(file);
		return err_create_file_mapping_failed;
	}

	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(file);
		return err_create_file_mapping_already_exists;
	}

	const auto mapping = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0);
	if (!mapping)
	{
		CloseHandle(file_mapping);
		CloseHandle(file);
		return err_map_file_failed;
	}

	suspend_threads();

	ret = replace_exec_section(module, mapping);

	NtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), nullptr, 0);

	resume_threads();

	if (ret)
	{
		UnmapViewOfFile(mapping);
		CloseHandle(file_mapping);
		CloseHandle(file);
		return ret;
	}

	UnmapViewOfFile(mapping);
	CloseHandle(file_mapping);
	CloseHandle(file);

	return err_success;
}


inline HMODULE add_module(const char* lib_name)
{
	auto module = GetModuleHandleA(lib_name);

	if (!module)
	{
		module = LoadLibraryA(lib_name);
	}

	return module;
}

inline DWORD unhook(const char* lib_name)
{
	const auto module = add_module(lib_name);

	const auto h_mod = unhook_module(module);

	FreeModule(module);

	return h_mod;
}

#endif
