#include"_tmain.h"
#ifdef _WIN64
UINT8	__shell_code[0x100] = {
	0x48,0x83,0xEC,0x28,	// sub rsp ,28h   //rcx rdx r8 r9  ���� 

	0x48,0x8D,0x0d,			// [+4] lea rcx,    
	0x00,0x00,0x00,0x00,	// [+7] DllFullPathOffset = [+43] - [+4] - 7
	// call ��ƫ�ƣ�����ַ����*��
	0xff,0x15,				// [+11]
	0x00,0x00,0x00,0x00,	// [+13] LoadLibraryAddressOffset

	0x48,0x83,0xc4,0x28,	// [+17] add rsp,28h

	// jmp ��ƫ�ƣ�����ַ����*��
	0xff,0x25,				// [+21]
	0x00,0x00,0x00,0x00,	// [+23] Jmp Rip

	// ���ԭ�ȵ� rip
	0x00,0x00,0x00,0x00,	// [+27]   //
	0x00,0x00,0x00,0x00,	// [+31]

	// ���� loadlibrary��ַ
	0x00,0x00,0x00,0x00,	// [+35] 
	0x00,0x00,0x00,0x00,	// [+39]

	// ���dll����·��
	//	0x00,0x00,0x00,0x00,	// [+43]
	//	0x00,0x00,0x00,0x00		// [+47]
	//	......
};

#else
UINT8	__shell_code[0x100] = {
	0x60,					// [+0] pusha   //����ջ˳����:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
	0x9c,					// [+1] pushf
	0x68,					// [+2] push
	0x00,0x00,0x00,0x00,	// [+3] ShellCode + 
	0xff,0x15,				// [+7] call	
	0x00,0x00,0x00,0x00,	// [+9] LoadLibrary Addr  Addr
	0x9d,					// [+13] popf
	0x61,					// [+14] popa
	0xff,0x25,				// [+15] jmp
	0x00,0x00,0x00,0x00,	// [+17] jmp  eip

	// eip ��ַ
	0x00,0x00,0x00,0x00,	// [+21]
	//LoadLibrary��ַ
	0x00,0x00,0x00,0x00,	// [+25] 
	//DllFullPath 
	0x00,0x00,0x00,0x00		// [+29] 


};
#endif
int _tmain(int argc,TCHAR* argv[]) {
   
	if (4 == argc) {
		if (_tcsicmp(argv[1],_T("1")) == 0){
			create_remote_thread_inject(argv[2],argv[3]);
		}
		else if (_tcsicmp(argv[1], _T("2")) == 0) {
			queue_user_apc_inject(argv[2], argv[3]);
		}
		else if (_tcsicmp(argv[1], _T("3")) == 0) {
			set_context_thread_inject(argv[2], argv[3]);
		}
		else if (_tcsicmp(argv[1], _T("4")) == 0) {
			set_window_hookex_inject(argv[2], argv[3]);
		}
	}
	else if (3 == argc&& _tcsicmp(argv[1], _T("5")) == 0) {
		register_inject(argv[2]);
	}
	return 0;
}
BOOL create_remote_thread_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name) {
	HANDLE target_process_id=0;
	HANDLE target_process_handle = NULL;
	target_process_id = _PROCESS_HELPER_::get_process_id(target_process_image_name);
	if (0== target_process_id) {
		return FALSE;
	}
    SIZE_T dll_name_length = 0;
    LPVOID dll_address = NULL;
    FARPROC function_proc_address = NULL;

    // ��ע�����
    target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)target_process_id);
    if (NULL == target_process_handle)
    {
        return FALSE;
    }

    // �õ�ע���ļ�������·��
    dll_name_length = sizeof(TCHAR) *(lstrlen(dll_name)+1);

    // �ڶԶ�����һ���ڴ�
    dll_address = VirtualAllocEx(target_process_handle, NULL, dll_name_length, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == dll_address)
    {
        return FALSE;
    }

    // ��ע���ļ���д�뵽�ڴ���
    if (FALSE == WriteProcessMemory(target_process_handle, dll_address, dll_name, dll_name_length, NULL))
    {
        return FALSE;
    }

    // �õ�LoadLibraryA()�����ĵ�ַ
#ifdef _UNICODE
    function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");
#else
    function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA");
#endif // _UNICODE
   
    if (NULL == function_proc_address)
    {
        return FALSE;
    }

    // �����߳�ע��
    HANDLE remote_thread_handle = CreateRemoteThread(target_process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)function_proc_address, dll_address, 0, NULL);
    if (NULL == remote_thread_handle)
    {
        return FALSE;
    }

    // �رվ��
    CloseHandle(target_process_handle);
    return TRUE;
 
}
BOOL queue_user_apc_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name)
{
    HANDLE target_process_id = _PROCESS_HELPER_::get_process_id(target_process_image_name);
    if (0 == target_process_id) {
        return FALSE;
    }
    FARPROC function_proc_address = NULL;
    // ��ע�����
    HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)target_process_id);
    if (NULL == target_process_handle)
    {
        return FALSE;
    }

    // �õ�ע���ļ�������·��
    SIZE_T dll_name_length = sizeof(TCHAR) * (lstrlen(dll_name) + 1);
    // �ڶԶ�����һ���ڴ�
    LPVOID dll_address = VirtualAllocEx(target_process_handle, NULL, dll_name_length, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == dll_address)
    {
        return FALSE;
    }

    // ��ע���ļ���д�뵽�ڴ���
    if (FALSE == WriteProcessMemory(target_process_handle, dll_address, dll_name, dll_name_length, NULL))
    {
        return FALSE;
    }

    // �õ�LoadLibrary�����ĵ�ַ
#ifdef _UNICODE
    function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");
#else
    function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA");
#endif // _UNICODE

    if (NULL == function_proc_address)
    {
        return FALSE;
    }
    THREADENTRY32 thread_entry = { 0 };
    thread_entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == snap_handle)
    {
        CloseHandle(target_process_handle);
        return FALSE;
    }
    if (Thread32First(snap_handle, &thread_entry))
    {
        do
        {
            // ����ID�Ա��Ƿ�Ϊ����Ľ���
            if (thread_entry.th32OwnerProcessID ==(DWORD)target_process_id)
            {
                // ���̣߳��õ��߳̾��
                HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
                if (thread_handle)
                {
                    // ���̲߳���APC����
                     QueueUserAPC((PAPCFUNC)function_proc_address, thread_handle, (ULONG_PTR)dll_address);
                    // �رվ��
                    CloseHandle(thread_handle);
                }
            }
            // ѭ����һ���߳�
        } while (Thread32Next(snap_handle, &thread_entry));
    }
    // �رվ��
    CloseHandle(snap_handle);
    return TRUE;
}
BOOL set_context_thread_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name)
{
	CONTEXT	thread_context = { 0 };
	BOOL    IsOk = FALSE;
	HANDLE  thread_handle= NULL;
	PUINT8	dll_path_place = NULL;
	HANDLE thread_id = NULL;
	std::vector<HANDLE> thread_ids;
	
	HANDLE target_process_id = _PROCESS_HELPER_::get_process_id(target_process_image_name);
	if (0 == target_process_id) {
		return FALSE;
	}
	FARPROC function_proc_address = NULL;
	// ��ע�����
	HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)target_process_id);
	if (NULL == target_process_handle)
	{
		return FALSE;
	}
	//Ŀ����̿ռ������ڴ�
	PVOID shell_code_address = VirtualAllocEx(target_process_handle, NULL,
		sizeof(__shell_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	SIZE_T dll_name_length = sizeof(TCHAR) * (lstrlen(dll_name) + 1);
#ifdef _UNICODE
	function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW");
#else
	function_proc_address = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryA");
#endif // _UNICODE

	if (NULL == shell_code_address)
	{
		//goto Exit;
		return FALSE;
	}
	_THREAD_HELPER_::get_thread_id(target_process_id,thread_ids);
	thread_id = thread_ids[0];
	//�������ָ��
#ifdef _WIN64
	//������̬������·��
	dll_path_place = __shell_code + 43;
	memcpy(dll_path_place, dll_name, dll_name_length);

	//lea rcx Offset
	UINT32 dll_path_offeset = (UINT32)(((PUINT8)shell_code_address + 43)
		- ((PUINT8)shell_code_address + 4) - 7);
	*(PUINT32)(__shell_code + 7) = dll_path_offeset;

	// ShellCode + 35�� ���� LoadLibrary ������ַ
	*(PUINT64)(__shell_code + 35) = (UINT64)function_proc_address;   //��ǰģ�鵼�����

	//ff15 Offset
	UINT32	load_library_address_offset = (UINT32)(((PUINT8)shell_code_address + 35) - ((PUINT8)shell_code_address + 11) - 6);
	*(PUINT32)(__shell_code + 13) = load_library_address_offset;


	//ͨ�����߳�ID������߳̾��
	thread_handle= OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)thread_id);

	if (NULL == thread_handle)
	{
		goto Exit;
	}

	//���ȹ����̻߳�ø��̵߳�RIP
	SuspendThread(thread_handle);   //����


	thread_context.ContextFlags = CONTEXT_ALL;  //ע�����߳����±�����ʱ 
	if (GetThreadContext(thread_handle, &thread_context) == FALSE)
	{
		goto Exit;
	}


	//����ԭ��RIP
	*(PUINT64)(__shell_code + 27) = thread_context.Rip;
	//��ShellCodeֱ��д�뵽Ŀ����̿ռ���
	if (FALSE == WriteProcessMemory(target_process_handle, shell_code_address, __shell_code, sizeof(__shell_code), NULL)) {
		goto Exit;
	}
	//HookIP
	thread_context.Rip = (UINT64)shell_code_address;
#else
	dll_path_place = __shell_code + 29;
	memcpy(dll_path_place, dll_name, dll_name_length);  //��Dll����·������Ŀ����̿ռ���   

	//Push Address 
	*(PULONG)(__shell_code + 3) = (ULONG)shell_code_address + 29;

	*(PULONG)(__shell_code + 25) = (ULONG)function_proc_address;   //��ǰexeģ���еĵ��뺯��

	*(PULONG_PTR)(__shell_code + 9) = (ULONG_PTR)shell_code_address + 25;

	//ͨ������ID������߳̾��
	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)thread_id);     //ͨ��Ŀ�����߳�ID������߳̾��

	if (thread_handle == NULL)
	{
		goto Exit;
	}
	//���ȹ����߳�
	SuspendThread(thread_handle);   //Ŀ������е����̹߳���   EIP
	thread_context.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(thread_handle, &thread_context) == FALSE)
	{
		goto Exit;
	}


	*(PULONG_PTR)(__shell_code + 21) = thread_context.Eip;
	*(PULONG_PTR)(__shell_code + 17) = (ULONG_PTR)shell_code_address + 21;

	if (FALSE == WriteProcessMemory(target_process_handle, shell_code_address, __shell_code, sizeof(__shell_code), NULL))
	{
		goto Exit;
	}
	//�����ڵ�ShellCode��Ϊ�µ�ָ��
	thread_context.Eip = (ULONG_PTR)shell_code_address;
#endif
	//���߳����±��������û��߳���
	if (!SetThreadContext(thread_handle, &thread_context))
	{
		goto Exit;
	}
	//�ָ��̼߳���ִ��
	ResumeThread(thread_handle);

	IsOk = TRUE;

Exit:
	if (shell_code_address != NULL)
	{
		VirtualFreeEx(target_process_id, shell_code_address, sizeof(__shell_code), MEM_RELEASE);
	}
	if (thread_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(thread_handle);
	}
	if (target_process_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(target_process_handle);
	}
	return IsOk;
}
BOOL set_window_hookex_inject(const TCHAR* target_process_image_name, const TCHAR* dll_name)
{
	HANDLE target_process_id = _PROCESS_HELPER_::get_process_id(target_process_image_name);
	if (0 == target_process_id) {
		return FALSE;
	}
	HANDLE thread_id = NULL;
	std::vector<HANDLE> thread_ids;
	_THREAD_HELPER_::get_thread_id(target_process_id, thread_ids);
	HMODULE module_base = LoadLibrary(dll_name);
	FARPROC inject_process_id_address = NULL;
	HHOOK hook_handle=NULL;
	if (NULL == module_base )
	{
		goto Exit;
	}

	inject_process_id_address = GetProcAddress(module_base, "inject_process_id");
	if (NULL == inject_process_id_address)
	{
		goto Exit;
	}
	for (int i = 0; i < thread_ids.size(); ++i)
	{
		hook_handle = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)inject_process_id_address, module_base, (DWORD)thread_ids[i]);
		if (hook_handle != NULL)
		{
			break;
		}
	}
Exit:
	if (hook_handle != NULL)
	{
		UnhookWindowsHookEx(hook_handle);  //Remove Dll 
		hook_handle = NULL;
	}

	if (thread_ids.empty() == false)
	{
		std::vector<HANDLE>().swap(thread_ids);
	}
	if (!!(thread_ids.size()))
	{
		//ThreadIdentify.~vector();
		std::vector<HANDLE>().swap(thread_ids);
	}
	if (module_base != NULL)
	{
		FreeLibrary(module_base);
		module_base = NULL;
	}
	return 0;
}
BOOL register_inject(const TCHAR* dll_name)
{
	
	HKEY key_handle;
	LPCWSTR key_value_1 = _T("AppInit_DLLs");      //��Ҫ���õ�ע�����
	LPCWSTR key_value_2 = _T("LoadAppInit_DLLs");  //��Ҫ���õ�ע�����
	LPCWSTR sub_key = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\");  //�Ӽ�·��
	DWORD LoadAppInitValue = 1;				//����ֵΪ1
	BYTE buffer_data[MAX_PATH] = {0};
	//��ע���
	LSTATUS retrun_value = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sub_key, 0, KEY_ALL_ACCESS, &key_handle);

	if (retrun_value != ERROR_SUCCESS)
	{
		printf("Open Key Failed!\n");
		return -1;
	}
	memcpy(buffer_data, dll_name, (_tcslen(dll_name) + 1) * sizeof(TCHAR));
	//����Dll·��
	retrun_value = RegSetValueEx(key_handle, key_value_1, 0, REG_SZ, buffer_data, (_tcslen(dll_name) + 1) * sizeof(TCHAR));
	if (retrun_value != ERROR_SUCCESS)
	{
		printf("Set DllPath Failed!\n");
		return -1;
	}

	//������������ʱ����Dll
	retrun_value = RegSetValueEx(key_handle, key_value_2, 0, REG_DWORD, (const BYTE*)&LoadAppInitValue, sizeof(DWORD));
	if (retrun_value != ERROR_SUCCESS)
	{
		printf("Set LoadAppInitValue Failed!\n");
		return -1;
	}

	RegCloseKey(key_handle);

	return 0;

}
