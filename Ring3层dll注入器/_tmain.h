#include<Windows.h>
#include<tchar.h>
#include<iostream>
#include <TlHelp32.h>
#include"ProcessHelper.h"
#include"ThreadHelper.h"
#include<vector>
#define WINDOWS  _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")	
BOOL create_remote_thread_inject(const TCHAR * target_process_image_name, const TCHAR* dll_name);
BOOL queue_user_apc_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name);
BOOL set_context_thread_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name);
BOOL set_window_hookex_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name);
BOOL register_inject(const TCHAR* dll_name);