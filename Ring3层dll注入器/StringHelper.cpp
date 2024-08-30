#include "StringHelper.h"

namespace _STRING_HELPER_ {
	BOOL char_2_wchar(WCHAR** destination_string, const char* source_string, SIZE_T source_string_length)
	{
		if (IsBadStringPtrA(source_string, source_string_length) == TRUE)
		{
			return FALSE;
		}
		size_t  destination_string_length = (size_t)MultiByteToWideChar(CP_ACP, 0,
			source_string, int(source_string_length), NULL, 0);   //计算单字转换成双字需要的内存长度

		*destination_string = new WCHAR[destination_string_length + 1];
		if (*destination_string == NULL)
		{
			return FALSE;
		}
		//真正转换
		MultiByteToWideChar(CP_ACP, 0, source_string, int(source_string_length), *destination_string, int(destination_string_length));

		return TRUE;
	}
}
