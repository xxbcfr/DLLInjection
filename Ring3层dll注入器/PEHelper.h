#pragma once
#include <iostream>
#include <Windows.h>
#include <tchar.h>


namespace _PE_HELPER_
{
	void* get_proc_address(HMODULE module_base, LPCCH key_word);  
	void  forword_export_get_address(void *&function_address);
};
