#define _WIN32_DCOM
#define COBJMACROS

#include "beacon.h"
#include "DriverQuery.h"
#include <wchar.h>
#include <stdarg.h>

#define NAME_WIDTH       16
#define DISP_NAME_WIDTH  32
#define TYPE_WIDTH       12

#define BATCH_LINES      20
#define BATCH_BUF_SIZE   16384

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif


// Normalize WMI-reported driver paths to a standard filesystem format.
// Handles common prefixes like \??\ and \SystemRoot\.

static void FixPath(const wchar_t* path, wchar_t* out, DWORD outSize) {
    if (!path || !*path) { out[0] = 0; return; }
    wchar_t temp[MAX_PATH];
    MSVCRT$wcsncpy_s(temp, MAX_PATH, path, _TRUNCATE);

    if (MSVCRT$wcsncmp(temp, L"\\??\\", 4) == 0)
        MSVCRT$wcscpy_s(temp, MAX_PATH, temp + 4);

    if (MSVCRT$wcsncmp(temp, L"\\SystemRoot\\", 12) == 0) {
        wchar_t replaced[MAX_PATH];
        MSVCRT$_snwprintf_s(replaced, MAX_PATH, _TRUNCATE, L"C:\\Windows\\%s", temp + 12);
        MSVCRT$wcsncpy_s(temp, MAX_PATH, replaced, _TRUNCATE);
    }

    if (!KERNEL32$ExpandEnvironmentStringsW(temp, out, outSize))
        MSVCRT$wcsncpy_s(out, outSize, temp, _TRUNCATE);
}


// Safely truncate wide strings to a fixed display width.
// Adds ellipsis ("...") if text exceeds the limit.

static void TruncateTo(wchar_t* out, size_t outElems, const wchar_t* in, int width) {
    if (!in || !*in) { out[0] = 0; return; }
    int len = (int)MSVCRT$wcslen(in);
    if (len <= width) {
        MSVCRT$wcsncpy_s(out, outElems, in, _TRUNCATE);
        return;
    }
    int cut = (width > 3) ? width - 3 : width;
    if ((size_t)cut >= outElems) cut = (int)outElems - 1;
    MSVCRT$wcsncpy_s(out, outElems, in, (rsize_t)cut);
    out[cut] = 0;
    if ((size_t)cut + 3 < outElems)
        MSVCRT$wcscat_s(out, outElems, L"...");
}


// Convert wide-character (UTF-16) strings to UTF-8 for Beacon output.

static int WideToUtf8(const wchar_t* w, char* out, int outSize) {
    int needed = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (needed <= 0 || needed > outSize) return 0;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outSize, NULL, NULL);
    return 1;
}


// - Initializes COM and connects to WMI (ROOT\CIMV2)
// - Queries Win32_SystemDriver to enumerate all system drivers
// - Collects Name, DisplayName, ServiceType, and PathName
// - Outputs results in batched text for Beacon display.

void go(char* args, int alen) {

    // Initialize COM for WMI
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed\n"); return; }

    // Initialize COM security
    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeSecurity failed\n");
        OLE32$CoUninitialize();
        return;
    }

    // Create WMI Locator
    IWbemLocator* pLoc = NULL;
    hr = OLE32$CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance failed\n");
        OLE32$CoUninitialize();
        return;
    }

    // Connect to ROOT\CIMV2 namespace
    IWbemServices* pSvc = NULL;
    BSTR ns = OLEAUT32$SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->lpVtbl->ConnectServer(pLoc, ns, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    OLEAUT32$SysFreeString(ns);
    if (FAILED(hr) || !pSvc) {
        BeaconPrintf(CALLBACK_ERROR, "ConnectServer failed\n");
        pLoc->lpVtbl->Release(pLoc);
        OLE32$CoUninitialize();
        return;
    }

    // Set security levels on WMI proxy
    hr = OLE32$CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoSetProxyBlanket failed\n");
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        OLE32$CoUninitialize();
        return;
    }

    // Execute WMI query for all system drivers
    IEnumWbemClassObject* pEnum = NULL;
    BSTR wql = OLEAUT32$SysAllocString(L"WQL");
    BSTR qry = OLEAUT32$SysAllocString(L"SELECT Name, DisplayName, PathName, ServiceType FROM Win32_SystemDriver");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, wql, qry,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
    OLEAUT32$SysFreeString(wql);
    OLEAUT32$SysFreeString(qry);
    if (FAILED(hr) || !pEnum) {
        BeaconPrintf(CALLBACK_ERROR, "ExecQuery failed\n");
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        OLE32$CoUninitialize();
        return;
    }

    // Initialize output batching buffer
    static char batch[BATCH_BUF_SIZE];
    int batch_offset = 0;
    int batch_lines = 0;

    // Print header line
    batch_offset += MSVCRT$_snprintf(batch + batch_offset, sizeof(batch) - batch_offset,
        "%-16s\t%-32s\t%-12s\t%s\n"
        "------------------------------------------------------------------------------------------------------------------------\n",
        "Name", "Display Name", "Type", "Path");

    ULONG total = 0;

    //
    // Main loop: iterate over all WMI driver objects
    //
    for (;;) {
        IWbemClassObject* pObj = NULL;
        ULONG uRet = 0;
        hr = pEnum->lpVtbl->Next(pEnum, 3000, 1, &pObj, &uRet);
        if (uRet == 0) break;

        VARIANT vtName, vtDisp, vtPath, vtType;
        OLEAUT32$VariantInit(&vtName);
        OLEAUT32$VariantInit(&vtDisp);
        OLEAUT32$VariantInit(&vtPath);
        OLEAUT32$VariantInit(&vtType);

        pObj->lpVtbl->Get(pObj, L"Name", 0, &vtName, 0, 0);
        pObj->lpVtbl->Get(pObj, L"DisplayName", 0, &vtDisp, 0, 0);
        pObj->lpVtbl->Get(pObj, L"PathName", 0, &vtPath, 0, 0);
        pObj->lpVtbl->Get(pObj, L"ServiceType", 0, &vtType, 0, 0);

        if (vtName.vt != VT_BSTR) {
            pObj->lpVtbl->Release(pObj);
            goto cleanup_variant;
        }

        // Normalize driver path
        wchar_t fixedPath[MAX_PATH];
        FixPath(vtPath.vt == VT_BSTR ? vtPath.bstrVal : L"", fixedPath, MAX_PATH);

        // Detect driver type (Kernel, File System, etc.)
        const wchar_t* t = L"Other";
        if (vtType.vt == VT_BSTR && MSVCRT$wcsstr(vtType.bstrVal, L"Kernel")) t = L"Kernel";
        else if (vtType.vt == VT_BSTR && MSVCRT$wcsstr(vtType.bstrVal, L"File System")) t = L"File System";

        // Format output line (truncated columns)
        wchar_t svcBuf[64];
        wchar_t dispBuf[256];
        TruncateTo(svcBuf, ARRAYSIZE(svcBuf), vtName.bstrVal, NAME_WIDTH);
        TruncateTo(dispBuf, ARRAYSIZE(dispBuf), (vtDisp.vt == VT_BSTR) ? vtDisp.bstrVal : vtName.bstrVal, DISP_NAME_WIDTH);

        wchar_t line[512];
        MSVCRT$_snwprintf_s(line, ARRAYSIZE(line), _TRUNCATE,
            L"%-*s\t%-*s\t%-*s\t%s\n",
            NAME_WIDTH, svcBuf,
            DISP_NAME_WIDTH, dispBuf,
            TYPE_WIDTH, t,
            fixedPath[0] ? fixedPath : L"(none)");

        // Convert to UTF-8 for Beacon output
        char utf8line[1024];
        if (!WideToUtf8(line, utf8line, sizeof(utf8line))) goto cleanup_variant;

        int lineLen = (int)MSVCRT$strlen(utf8line);

        // Output in batches to avoid truncation
        if (batch_offset + lineLen >= (int)sizeof(batch) - 64 || batch_lines >= BATCH_LINES) {
            BeaconOutput(CALLBACK_OUTPUT, batch, batch_offset);
            batch_offset = 0;
            batch_lines = 0;
            batch_offset += MSVCRT$_snprintf(batch + batch_offset, sizeof(batch) - batch_offset,
                "%-16s\t%-32s\t%-12s\t%s\n"
                "------------------------------------------------------------------------------------------------------------------------\n",
                "Name", "Display Name", "Type", "Path");
        }

        // Append line to batch
        MSVCRT$memcpy(batch + batch_offset, utf8line, (size_t)lineLen);
        batch_offset += lineLen;
        batch_lines++;
        total++;

    cleanup_variant:
        OLEAUT32$VariantClear(&vtName);
        OLEAUT32$VariantClear(&vtDisp);
        OLEAUT32$VariantClear(&vtPath);
        OLEAUT32$VariantClear(&vtType);
    }

    // Flush remaining output
    if (batch_offset > 0)
        BeaconOutput(CALLBACK_OUTPUT, batch, batch_offset);
    else if (total == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[i] No drivers found.\n");

    // Cleanup COM objects
    pEnum->lpVtbl->Release(pEnum);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    OLE32$CoUninitialize();
}
