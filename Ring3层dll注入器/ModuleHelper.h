#pragma once
#include <iostream>
#include <Windows.h>
#include <tchar.h>
namespace  _MODULE_HELPER_
{
#ifdef UNICODE
#define get_module_handle  get_module_handle_w
#else
#define get_module_handle  get_module_handle_a
#endif // !UNICODE
	HMODULE get_module_handle_a(const char* module_name);
	HMODULE get_module_handle_w(const WCHAR* module_name);

};