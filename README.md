# HandleHijacker

![Go](https://img.shields.io/badge/Language-Go-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**HandleHijacker** is a low-level Windows utility written in Go that lets you inspect running processes, extract files that processes have open, and optionally close handles to those files. It uses Windows native APIs (`ntdll.dll` and `kernel32.dll`) to enumerate handles and read files directly from another process.

> ⚠️ **Warning:** This tool performs advanced and potentially disruptive operations on processes and file handles. Use only on systems you own or where you have explicit permission. Terminating handles or modifying other processes can crash programs or cause data loss.

---

## Quick links

- [Download](#) — build from source
- [Usage](#usage)
- [Security & Disclaimer](#security-considerations)
- [License](#license)

---

## Features

- Scan running processes by name (e.g. `chrome.exe`).
- Enumerate open handles for each process.
- Extract a specific file opened by a process and save it to disk.
- Optionally close the handle inside the target process after extraction.

---

## Requirements

- Windows 10 / 11 (or compatible)
- Brain
---

## Usage

Run the program and follow the prompts:

```bash
HandleHijacker.exe
```

Prompts explained:

1. **Target process name** — the process to scan (e.g. `chrome.exe`).
2. **File to hijack** — file base name to search for among open handles (e.g. `Cookies`).
3. **Output file path** — where to save the extracted file (e.g. `Cookies.dmp`).
4. **Close handle after?** — `y` to attempt to close the handle in the target process.

### Example session

```
Target process name: chrome.exe
File to hijack: Cookies
Output file path: Cookies.dmp
Close handle after? (y/n): y

>>> Hijacking: Cookies from chrome.exe
>>> Scanning 1 instance(s)
... PID 1234 (4 handles)

*** FOUND ***
  Location: Cookies
  PID: 1234
  Handle: 0x1F4
  Size: 1024 bytes
>>> Saved to: Cookies.dmp
>>> Handle terminated

>>> Complete!
```

---

## Security considerations & warnings

- **Do not** use this against systems you do not own or have permission to test.
---

## Contributing

Contributions are welcome but please follow this rule:

- Keep code changes focused and well-documented.

---

## About

Created as an advanced example for educational purposes. The author is not responsible for misuse. Use only with permission and be mindful of safety and legal constraints.


## Credits;
- **tigr0w / ZeroMemoryEx_Handle-Ripper** — Primary inspiration for handle enumeration and ripper techniques: https://github.com/tigr0w/ZeroMemoryEx_Handle-Ripper. The algorithms for querying process handle tables and duplicating handles were especially useful.  
- Stackoverflow
