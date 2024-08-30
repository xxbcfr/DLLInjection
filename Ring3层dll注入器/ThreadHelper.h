#pragma once
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include<TlHelp32.h>
#include<vector>
namespace _THREAD_HELPER_ {
	BOOL get_thread_id(HANDLE process_id, std::vector<HANDLE>& thread_id);
};