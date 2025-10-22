## Overview

`DriverQuery` is a Cobalt Strike **Beacon Object File (BOF)** for enumerating Windows system drivers via **Windows Management Instrumentation (WMI)**.  

- Queries WMI class `Win32_SystemDriver` via COM (`IWbemLocator` → `IWbemServices::ExecQuery`).
- Results are normalized for readability (e.g., resolving `\SystemRoot\` to `C:\Windows\`).
- Output is batched to prevent truncation and optimize large result sets.

Results are displayed in a structured table format for readability and batch output compatibility.

![BOF output](/src/1.png)


## Disclaimer
This project was thrown together to quickly enumerate system drivers in a post-exploitation context.  
It is provided **as-is**, without warranty or guarantee of correctness or completeness.

> Use at your own risk and with needed permissions.

## Credits
This is a budget version off the native Windows `driverquery.exe` tool and the  [OffensiveCSharp](https://github.com/matterpreter/OffensiveCSharp) implementation. 
