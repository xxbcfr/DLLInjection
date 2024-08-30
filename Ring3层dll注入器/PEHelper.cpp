#include "PEHelper.h"
#include "ModuleHelper.h"
#include <Dbghelp.h>
#pragma comment(lib,"Dbghelp.lib")
namespace _PE_HELPER_
{
	void* get_proc_address(HMODULE module_base, LPCCH key_word)
	{
		char* module_base_address = (char*)module_base;

		IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)module_base_address;
		IMAGE_NT_HEADERS* image_nt_headers = (IMAGE_NT_HEADERS*)((size_t)module_base_address + image_dos_header->e_lfanew);

		IMAGE_OPTIONAL_HEADER* image_optional_header = &image_nt_headers->OptionalHeader;
		IMAGE_DATA_DIRECTORY* image_data_directory = (IMAGE_DATA_DIRECTORY*)(&image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		IMAGE_EXPORT_DIRECTORY* image_export_directory = (IMAGE_EXPORT_DIRECTORY*)((size_t)module_base_address + image_data_directory->VirtualAddress);
		
		if (image_export_directory->NumberOfNames == 0 || image_export_directory->NumberOfFunctions == 0)
		{
			return NULL;
		}

		DWORD* address_of_functions = (DWORD*)((size_t)module_base_address + image_export_directory->AddressOfFunctions);
		DWORD* address_of_names = (DWORD*)((size_t)module_base_address + image_export_directory->AddressOfNames);
		WORD* address_of_name_ordinals = (WORD*)((size_t)module_base_address + image_export_directory->AddressOfNameOrdinals);

		void* function_address = NULL;
		DWORD i;

		//索引导出
		if (((ULONG_PTR)key_word >> 16) == 0)
		{
			WORD ordinal = LOWORD(key_word);
			ULONG_PTR base = image_export_directory->Base;

			if (ordinal < base || base > base + image_export_directory->NumberOfFunctions)
			{
				return NULL;
			}
			function_address = (void*)((size_t)module_base_address + address_of_functions[ordinal - base]);
		}
		else  //函数名称导出
		{
			for (i = 0; i < image_export_directory->NumberOfNames; i++)
			{

				//获得函数名称
				char* FunctionName = (char*)((size_t)module_base_address + address_of_names[i]);
				if (_stricmp(key_word, FunctionName) == 0)
				{
					function_address = (void*)((size_t)module_base_address + address_of_functions[address_of_name_ordinals[i]]);
					break;
				}
			}
		}

		//函数转发器
		if ((char*)function_address >= (char*)image_export_directory &&(char*)function_address < (char*)image_export_directory + image_data_directory->Size)
		{
			forword_export_get_address(function_address);
		}
		return function_address;
	}
	void forword_export_get_address(void*& function_address)
	{
		HMODULE forward_module_base = 0;

		//获得转发模块的名称
		//FunctionAddress =  //Dll.Sub_1........  Dll.#2
		char* forword_module_function_name = _strdup((char*)function_address);
		if (!forword_module_function_name)
		{
			function_address = NULL;
			return ;
		}
		char* function_name = strchr(forword_module_function_name, '.');
		*function_name++ = 0;

		function_address = NULL;

		//构建转发模块的路径
		char full_path[MAX_PATH] = { 0 };
		strcpy_s(full_path, forword_module_function_name);
		strcat_s(full_path, strlen(forword_module_function_name) + 4 + 1, ".dll");

		//判断是不是当前进程已经加载了这个转发模块
		forward_module_base = (HMODULE)_MODULE_HELPER_::get_module_handle_a(full_path);
		if (!forward_module_base)
		{
			forward_module_base = LoadLibraryA(full_path);
		}

		if (!forward_module_base)
		{
			function_address = NULL;
			return ;
		}


		BOOL is_ordinal = strchr(forword_module_function_name, '#') == 0 ? FALSE : TRUE;
		if (is_ordinal)
		{
			//函数索引转发
			WORD function_ordinal = atoi(forword_module_function_name + 1);
			//递归自己
			function_address = (char *)_PE_HELPER_::get_proc_address(forward_module_base, (const char*)function_ordinal);
		}
		else
		{
			//函数名称转发
			function_address = _PE_HELPER_::get_proc_address(forward_module_base, function_name);
		}

		free(forward_module_base);
	}
}