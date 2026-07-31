

## 📌 Description
XwormKiller -  is a specialized utility designed to detect and eliminate 
XWorm RAT and similar Remote Access Trojans from infected Windows systems. 
It performs deep system analysis, process monitoring, and automatic cleanup.

## ✨ Features
- 🛡️ Deep Protection (custom hunter) – auto-engages the moment the primary scan finds no trace of the RAT; a hard time-boxed (5–10s) parallel sweep of running processes, deep user-writable folders, script stubs, WMI event-consumer persistence and covert C2 owners, with automatic quarantine
- 🧠 Weighted threat scoring – every process/file is scored across many signals instead of a single name match, drastically cutting false positives while catching more real threats
- ✍️ Authenticode verification – validates digital signatures via WinVerifyTrust (full chain check, not just presence)
- 📈 Entropy analysis – flags packed / encrypted payloads by measuring Shannon entropy
- 🧬 .NET image detection – reads the PE header to identify managed assemblies (XWorm and most commodity RATs are .NET)
- 🔎 Static signature scanning – searches binaries for XWorm markers and process-injection / loader indicators
- 🧵 Command-line & process-tree analysis – detects encoded PowerShell, LOLBin abuse, MSBuild inline-task loaders, and macro-dropper spawn chains (via WMI)
- 🌐 Network C2 analysis – parses active connections and flags ESTABLISHED links to remote RAT ports
- 🛡️ System process integrity check – verifies svchost.exe, explorer.exe, MSBuild.exe against path spoofing and DLL injection
- 🕵️ IFEO hijack detection – finds and removes Image File Execution Options debugger persistence
- 🔥 Active port scanning – detects open RAT ports and terminates associated processes
- 🚫 Firewall blocking – adds inbound/outbound rules to block RAT communication
- 🧹 Registry cleanup – removes autorun entries (with binary analysis of targets), scheduled tasks, and startup folder items
- 💾 Cache wipe – cleans temporary files, prefetch, and recycle bin
- 🎨 Colored console output – intuitive visual feedback with color-coded warnings
- 🔄 Self-protection – prevents the tool from terminating itself

© XeoTeam. All rights reserved.
Telegram: @silidation


![Скриншот-20260409-222038](https://github.com/user-attachments/assets/e177eb45-bd1a-47b5-8d8c-e0e5cc4414ee)
