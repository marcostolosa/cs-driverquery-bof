// DriverQuery.h
#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdarg.h>

/* ---- WMI GUIDs required by CoCreateInstance (WbemLocator) ---- */
static const GUID CLSID_WbemLocator =
    {0x4590F811,0x1D3A,0x11D0,{0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
static const GUID IID_IWbemLocator =
    {0xDC12A687,0x737F,0x11CF,{0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

/* ---- WinTrust GUID (explicitly defined) ---- */
static const GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 =
    { 0x00AAC56B, 0xCD44, 0x11D0, {0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0xAA, 0xE4} };

/* ---- OLE32 (COM base) ---- */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(PVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);

/* ---- OLEAUT32 (BSTR / VARIANT) ---- */
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);

/* ---- KERNEL32 (misc) ---- */
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT int   WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

/* ---- MSVCRT (wide string / formatting helpers) ---- */
DECLSPEC_IMPORT int    __cdecl MSVCRT$_vsnwprintf_s(wchar_t*, size_t, size_t, const wchar_t*, va_list);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snwprintf_s(wchar_t*, size_t, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcsncpy_s(wchar_t*, rsize_t, const wchar_t*, rsize_t);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcscpy_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcscat_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$wcsncmp(const wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wint_t  __cdecl MSVCRT$towlower(wint_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$snprintf(char *buffer, size_t count, const char *format, ...);


/* ---- CRT ASCII helpers (BOF must import these explicitly) ---- */
DECLSPEC_IMPORT char*   __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_snprintf(char *buffer, size_t count, const char *format, ...);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char *str);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);

/* ---- WINTRUST / CRYPT32 ---- */
DECLSPEC_IMPORT LONG WINAPI WINTRUST$WinVerifyTrust(HWND, GUID*, LPVOID);
DECLSPEC_IMPORT CRYPT_PROVIDER_DATA* WINAPI WINTRUST$WTHelperProvDataFromStateData(HANDLE);
DECLSPEC_IMPORT CRYPT_PROVIDER_SGNR*  WINAPI WINTRUST$WTHelperGetProvSignerFromChain(CRYPT_PROVIDER_DATA*, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT CRYPT_PROVIDER_CERT*  WINAPI WINTRUST$WTHelperGetProvCertFromChain(CRYPT_PROVIDER_SGNR*, DWORD);
DECLSPEC_IMPORT DWORD WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif
