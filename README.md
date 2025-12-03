# KafraPacketSeeker

KafraPacketSeeker is a lightweight DLL designed to intercept, monitor, and debug **send/recv** network packets in applications that use **Winsock (ws2_32.dll)**.  
It is primarily intended for protocol research, client analysis, and debugging in Ragnarok Online environments.

The DLL works by hooking the Winsock `send` and `recv` functions, capturing packet headers and their sizes in real time.

---

## ✨ Features

- ✔️ Intercepts `recv()`  
- ✔️ Intercepts `send()`  
- ✔️ Optional hooking of both directions via macros  
- ✔️ Logs to console **or** file  
- ✔️ Compatible with hotpatched functions  
- ✔️ Zero external dependencies  
- ✔️ Works on any Windows application using Winsock  

---

## 🧩 How It Works

The DLL performs:

1. Loads the system's `ws2_32.dll`.
2. Locates the exported `send` and `recv` functions.
3. Installs a hotpatch-style JMP hook.
4. Reads the first 2 bytes (packet header).
5. Logs the header and packet size.

### Log example:
```
Packet Header: 0x0072 /Size: 31
Packet Header: 0x0089 /Size: 14
Packet Header: 0x01AB /Size: 7
```

---

## ⚙️ Configuration (Macros)

You can enable or disable specific behaviors through `config.h`:

| Macro              | Description                              |
|--------------------|------------------------------------------|
| `HOOK_SEND`        | Log only outgoing packets                |
| `HOOK_RECEIVED`    | Log only incoming packets                |
| `HOOK_BOTH`        | Log both directions                      |
| `USE_CONSOLE_LOG`  | Output log to console instead of file    |

Example:

```cpp
#define HOOK_BOTH
#define USE_CONSOLE_LOG
```

## 🛠️ Building

### Requirements

- Visual Studio 2019 or 2022  
- Windows SDK installed  
- Project type: **DLL (Dynamic Link Library)**  
- C++17 or newer  

### Build Steps

1. Open the project in Visual Studio  
2. Select **Release | Win32**  
3. Build → Generates `KafraPacketSeeker.dll`

---

## 📥 Injection

Use any DLL injector of your choice:

- Nemo  
- Warp  
- Custom loader
- Or just rename to .asi and put into RO folder with audio on.

Example via Warp:
Enable Patch: Load Custom DLL
Edit DLLSpec.yml to:
  Name: KafraPacketSeeker.dll
  Funcs:
    - Name: "Winsockhook"
    
---

⚠️ Legal Notice

This project is intended for:

- protocol research
- debugging
- educational reverse engineering

Do not use it for malicious purposes or on official servers.

---

💙 Contributing

Pull requests, improvements, and bug fixes are welcome.

---
