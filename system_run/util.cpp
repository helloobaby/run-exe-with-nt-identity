#pragma once
#include "util.h"
#include <cstdio>


template <typename T>
void DisplayError(T out_func){

    LPVOID lpMsgBuf;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
        | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    out_func((const wchar_t*)lpMsgBuf);

    LocalFree(lpMsgBuf);

}

 
template void DisplayError<decltype(&wprintf)>(decltype((&wprintf)));