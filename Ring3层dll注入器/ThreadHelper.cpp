#include"ThreadHelper.h"

namespace _THREAD_HELPER_ {

	BOOL get_thread_id(HANDLE process_id, std::vector<HANDLE>& thread_id)
	{

		BOOL return_value = FALSE;
		HANDLE snap_shot_handle = INVALID_HANDLE_VALUE;
		THREADENTRY32	thread_entry = { 0 };
		thread_entry.dwSize = sizeof(THREADENTRY32);
		snap_shot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snap_shot_handle == INVALID_HANDLE_VALUE)
		{
			goto Exit;
		}
		if (!Thread32First(snap_shot_handle, &thread_entry))
		{
			goto Exit;
		}
		do
		{
			if (thread_entry.th32OwnerProcessID == (DWORD)process_id)
			{

				thread_id.emplace_back((HANDLE)thread_entry.th32ThreadID);
				return_value = TRUE;
			}

		} while (Thread32Next(snap_shot_handle, &thread_entry));
	Exit:

		if (snap_shot_handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(snap_shot_handle);
		}
		snap_shot_handle = INVALID_HANDLE_VALUE;
		return return_value;
	}
}

