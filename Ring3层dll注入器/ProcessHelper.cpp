#include"ProcessHelper.h"
#include"ModuleHelper.h"
#include"SystemHelper.h"
#include"PEHelper.h"
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
namespace  _PROCESS_HELPER_ {
	void* get_peb_address()
	{
#ifdef _WIN64
		return (void*)__readgsqword(0x60);
#else
		return (void*)__readfsdword(0x30);
#endif

	}
	HANDLE get_process_id(const TCHAR* image_name)
	{
		ULONG buffer_length = 0x1000;
		void* buffer_data = NULL;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH; 
		HMODULE moudle_base = (HMODULE)_MODULE_HELPER_::get_module_handle(_T("ntdll.dll"));
		
		LPFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation_Pointer =
			(LPFN_NTQUERYSYSTEMINFORMATION)_PE_HELPER_::get_proc_address(moudle_base, "NtQuerySystemInformation");
		if (NtQuerySystemInformation_Pointer == NULL)
		{
			return NULL;
		}
		//获得当前进程默认堆
		void* heap_handle = GetProcessHeap();

		HANDLE process_id = 0;
		
		BOOL is_loop = FALSE;
		BOOL is_sucess = FALSE;
		//这里大括号嵌套有点多，用TlHelper简单少一点
		while (!is_loop)
		{
			//在当前进程的默认堆中
			buffer_data = HeapAlloc(heap_handle, HEAP_ZERO_MEMORY, buffer_length);  //当前进程默认堆申请内存
			if (buffer_data == NULL)
			{
				return NULL;
			}
			status = NtQuerySystemInformation_Pointer(SystemProcessInformation, buffer_data, buffer_length, &buffer_length);
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				is_sucess = TRUE;
				HeapFree(heap_handle, NULL, buffer_data);
				buffer_length *= 2;
			}
			else if (!NT_SUCCESS(status))   //不是内存不够的报错
			{
				HeapFree(heap_handle, NULL, buffer_data);
				return 0;
			}
			else
			{
				is_sucess = FALSE;
				PSYSTEM_PROCESS_INFORMATION system_process_info = (PSYSTEM_PROCESS_INFORMATION)buffer_data;
				while (system_process_info)
				{

					if (system_process_info->UniqueProcessId == 0)
					{

					}
					else
					{
#ifdef _UNICODE
						if (_wcsicmp(system_process_info->ImageName.Buffer, image_name) == 0)
						{
							process_id = system_process_info->UniqueProcessId;
							is_sucess = TRUE;

							break;
						}
#else
						char walk_image_name[MAX_PATH];
						memset(walk_image_name, 0, sizeof(walk_image_name));
						WideCharToMultiByte(0, 0, system_process_info->ImageName.Buffer, system_process_info->ImageName.Length, walk_image_name,
							MAX_PATH, NULL, NULL);
						if (_stricmp(image_name, walk_image_name) == 0)
						{
							process_id = system_process_info->UniqueProcessId;
							is_sucess = TRUE;

							break;
						}
#endif // _UNICODE


					}

					if (!system_process_info->NextEntryOffset)
					{
						break;
					}

					system_process_info = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)system_process_info + system_process_info->NextEntryOffset);
				}
				if (buffer_data)
				{
					HeapFree(heap_handle, NULL, buffer_data);
				}

			}
			if (process_id != 0)
			{
				break;
			}
			else if (!is_sucess)
			{
				// Don't continuously search...
				break;
			}
		}
		return process_id;
	}
}