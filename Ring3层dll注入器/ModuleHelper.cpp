#include "ModuleHelper.h"
#include "ProcessHelper.h"
HMODULE _MODULE_HELPER_::get_module_handle_a(const char* module_name)
{
	HMODULE module_base = NULL;
	WCHAR* module_name_w = NULL;
	_STRING_HELPER_::char_2_wchar(&module_name_w, module_name, strlen(module_name));

	if (module_name_w != NULL)
	{
		module_base = get_module_handle_w(module_name_w);
		delete module_name_w;
		module_name_w = NULL;
	}

	return module_base;
}

HMODULE _MODULE_HELPER_::get_module_handle_w(const WCHAR* module_name)
{
	void* module_base= 0;

	
	_PEB* peb = (_PEB*)_PROCESS_HELPER_::get_peb_address();
	



	PPEB_LDR_DATA peb_ldr_data = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY ldr_data_table_entry = (PLDR_DATA_TABLE_ENTRY)peb_ldr_data->InLoadOrderModuleList.Flink;

	while (ldr_data_table_entry->DllBase)
	{


		if (_wcsicmp(module_name, ldr_data_table_entry->BaseDllName.Buffer) == 0)
		{
			//获得模块在进程中的地址
			module_base = ldr_data_table_entry->DllBase;
			break;
		}
		ldr_data_table_entry = (PLDR_DATA_TABLE_ENTRY)ldr_data_table_entry->InLoadOrderModuleList.Flink;
	}
	return (HMODULE)module_base;
}
