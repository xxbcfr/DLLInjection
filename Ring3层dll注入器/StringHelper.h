#pragma once
#include <iostream>
#include <Windows.h>
#include <tchar.h>
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PSTR   Buffer;
} ANSI_STRING;
typedef ANSI_STRING* PANSI_STRING;
namespace _STRING_HELPER_ {
	BOOL char_2_wchar(WCHAR** destination_string, const char* source_string, SIZE_T source_string_length);
}