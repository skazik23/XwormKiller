using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WormKiller
{
    // How confident we are that something is malicious.
    enum ThreatLevel
    {
        Clean,      // score < 15
        Low,        // 15..39  - log only
        Suspicious, // 40..69  - warn, do not kill automatically
        Malicious   // >= 70   - terminate
    }

    // Accumulated verdict for a single process/file. Instead of the old
    // "does the name contain 'client'?" one-shot check we sum weighted
    // signals, which makes detection both deeper and far less trigger-happy.
    class ThreatReport
    {
        public string Target = "";
        public int Score;
        public readonly List<string> Reasons = new List<string>();

        public ThreatLevel Level =>
            Score >= 70 ? ThreatLevel.Malicious :
            Score >= 40 ? ThreatLevel.Suspicious :
            Score >= 15 ? ThreatLevel.Low :
                          ThreatLevel.Clean;

        public void Add(int weight, string reason)
        {
            if (weight <= 0) return;
            Score += weight;
            Reasons.Add($"(+{weight}) {reason}");
        }
    }

    // Lightweight snapshot of process metadata gathered via WMI. Pulling
    // command line + parent in one query is far cheaper than per-process
    // P/Invoke and lets us reason about process trees.
    class ProcessMeta
    {
        public int Pid;
        public int ParentPid;
        public string Name = "";
        public string ExecutablePath = "";
        public string CommandLine = "";
    }

    static class ThreatAnalyzer
    {
        // Directories a legitimate signed system binary should never run from.
        static readonly string[] SuspiciousDirs =
        {
            "\\temp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
            "\\appdata\\local\\", "\\downloads\\", "\\desktop\\", "\\public\\",
            "\\programdata\\", "\\windows\\temp\\", "\\.cache\\",
            "\\music\\", "\\videos\\", "\\pictures\\", "\\documents\\"
        };

        // High-confidence XWorm / .NET RAT byte-string markers. A single hit
        // is very strong evidence, so these carry a heavy weight.
        static readonly string[] HighConfidenceSignatures =
        {
            "XWorm", "Xwormmm", "XLogger", "XClient", "Xworm V",
            "SendPlugin", "savePlugin", "RunPlugin", "gotPlugin",
            "PCRestart", "StartDDos", "StopDDos", "StartReport",
            "offline Keylogger", "InjRun", "TrafficCounter",
            "Chrome_Killer", "AsyncMouse", "RunBotKiller"
        };

        // Generic loader / injection techniques favoured by XWorm stubs.
        // Weaker individually; several together push the score up.
        static readonly string[] LoaderIndicators =
        {
            "AddInProcess", "CreateRemoteThread", "VirtualAllocEx",
            "WriteProcessMemory", "ResumeThread", "SetThreadContext",
            "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
            "FromBase64String", "GZipStream", "Aes"
        };

        // Cache verdicts per file so the monitor loop does not re-hash and
        // re-verify the same binary every second.
        static readonly Dictionary<string, (DateTime when, ThreatReport report)> _cache =
            new Dictionary<string, (DateTime, ThreatReport)>(StringComparer.OrdinalIgnoreCase);
        static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(2);

        // ---- Public entry points -------------------------------------------------

        // Analyze a running process by PID. Combines runtime signals (name,
        // path, loaded modules, parent, command line) with static file analysis.
        public static ThreatReport AnalyzeProcess(Process proc, ProcessMeta? meta)
        {
            var report = new ThreatReport { Target = $"{proc.ProcessName} (PID {proc.Id})" };

            string lowerName = proc.ProcessName.ToLowerInvariant();

            // 1. Static file analysis of the main image.
            string path = SafeMainModulePath(proc);
            if (!string.IsNullOrEmpty(path))
            {
                var fileReport = AnalyzeFile(path);
                report.Score += fileReport.Score;
                report.Reasons.AddRange(fileReport.Reasons);
            }

            // 2. Impersonation of a critical system process from a wrong path.
            if (IsCriticalName(lowerName) && !string.IsNullOrEmpty(path) && !IsTrustedSystemPath(path))
            {
                report.Add(60, $"critical name '{lowerName}' running from non-system path: {path}");
            }

            // 3. DLL injection: a module loaded from a user-writable directory.
            try
            {
                foreach (ProcessModule module in proc.Modules)
                {
                    string modPath = module.FileName ?? "";
                    if (LooksSuspiciousLocation(modPath) && modPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        report.Add(45, $"module loaded from suspicious location: {module.FileName}");
                        break;
                    }
                }
            }
            catch { /* access denied on protected processes */ }

            // 4. Command-line heuristics (encoded PowerShell, LOLBin abuse).
            if (meta != null && !string.IsNullOrEmpty(meta.CommandLine))
            {
                AnalyzeCommandLine(lowerName, meta.CommandLine, report);
            }

            // 5. Process-tree anomaly: RAT stubs are commonly spawned by
            //    Office apps, browsers or script hosts.
            if (meta != null && meta.ParentPid > 0)
            {
                AnalyzeParent(lowerName, meta.ParentPid, report);
            }

            return report;
        }

        // Analyze a file on disk without needing a live process. Used for
        // startup file scans and for autorun / task targets.
        public static ThreatReport AnalyzeFile(string path)
        {
            if (_cache.TryGetValue(path, out var cached) && DateTime.Now - cached.when < CacheTtl)
                return cached.report;

            var report = new ThreatReport { Target = path };
            try
            {
                if (!File.Exists(path)) return report;

                var info = new FileInfo(path);

                // Location.
                if (LooksSuspiciousLocation(path))
                    report.Add(15, "image located in a user-writable directory");

                // Authenticode signature (real chain validation, not just presence).
                if (!IsAuthenticodeTrusted(path))
                {
                    // Unsigned is only meaningful for executables outside system dirs.
                    if (!IsTrustedSystemPath(path))
                        report.Add(20, "binary is unsigned or has an untrusted signature");
                }

                // Managed (.NET) image: XWorm and most modern commodity RATs are .NET.
                bool isDotNet = IsDotNetAssembly(path);
                if (isDotNet && LooksSuspiciousLocation(path))
                    report.Add(15, ".NET assembly running from a user-writable directory");

                // Entropy: packed / encrypted payloads sit near 8.0.
                double entropy = FileEntropy(path);
                if (entropy > 7.2)
                    report.Add(20, $"high entropy {entropy:F2} (packed/encrypted payload)");
                else if (entropy > 6.8 && isDotNet)
                    report.Add(10, $"elevated entropy {entropy:F2} for a .NET image");

                // Static signature scan.
                int sigHits = ScanForSignatures(path, HighConfidenceSignatures);
                if (sigHits > 0)
                    report.Add(55, $"matched {sigHits} XWorm signature string(s)");

                int loaderHits = ScanForSignatures(path, LoaderIndicators);
                if (loaderHits >= 3)
                    report.Add(30, $"contains {loaderHits} process-injection / loader indicators");
                else if (loaderHits > 0)
                    report.Add(loaderHits * 5, $"contains {loaderHits} loader indicator(s)");

                // Freshly-dropped tiny executables in temp are a classic stub pattern.
                if (LooksSuspiciousLocation(path) && info.Length < 2_000_000 &&
                    (DateTime.Now - info.CreationTimeUtc) < TimeSpan.FromDays(2))
                    report.Add(10, "small, recently-created executable in a temp/user directory");
            }
            catch { /* locked / access denied */ }

            _cache[path] = (DateTime.Now, report);
            return report;
        }

        // ---- Command line / parent analysis -------------------------------------

        static void AnalyzeCommandLine(string procName, string cmd, ThreatReport report)
        {
            string lower = cmd.ToLowerInvariant();

            if (procName is "powershell" or "pwsh")
            {
                if (lower.Contains("-enc") || lower.Contains("-encodedcommand") || lower.Contains(" -e "))
                    report.Add(40, "PowerShell launched with an encoded command");
                if (lower.Contains("frombase64string") || lower.Contains("downloadstring") ||
                    lower.Contains("invoke-expression") || lower.Contains("iex(") || lower.Contains("iex "))
                    report.Add(30, "PowerShell download/exec cradle in command line");
                if (lower.Contains("-w hidden") || lower.Contains("-windowstyle hidden") || lower.Contains("-nop"))
                    report.Add(15, "PowerShell hidden/no-profile execution");
            }

            if (procName == "msbuild")
            {
                // XWork/AsyncRAT loaders abuse MSBuild inline tasks to run C#.
                if (lower.Contains(".csproj") || lower.Contains(".xml") || lower.Contains("temp"))
                    report.Add(35, "MSBuild invoked with an external project (inline-task loader pattern)");
            }

            if (procName is "mshta" or "wscript" or "cscript" or "regsvr32" or "rundll32")
            {
                if (lower.Contains("http") || lower.Contains("javascript:") || lower.Contains("vbscript:") ||
                    lower.Contains("scrobj") || lower.Contains("appdata") || lower.Contains("temp"))
                    report.Add(30, $"{procName} executing remote/temporary content (LOLBin abuse)");
            }

            if (lower.Contains("frombase64string") || lower.Contains("::frombase64"))
                report.Add(10, "base64 decode on the command line");
        }

        static void AnalyzeParent(string childName, int parentPid, ThreatReport report)
        {
            string parentName;
            try { parentName = Process.GetProcessById(parentPid).ProcessName.ToLowerInvariant(); }
            catch { return; }

            string[] documentApps =
            {
                "winword", "excel", "powerpnt", "outlook", "onenote",
                "acrord32", "acrobat", "wordpad"
            };
            string[] scriptHostChildren =
            {
                "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
                "regsvr32", "rundll32", "msbuild", "installutil", "certutil"
            };

            bool parentIsDoc = Array.IndexOf(documentApps, parentName) >= 0;
            bool childIsScriptHost = Array.IndexOf(scriptHostChildren, childName) >= 0;

            if (parentIsDoc && childIsScriptHost)
                report.Add(40, $"script host '{childName}' spawned by document app '{parentName}' (macro dropper pattern)");

            if ((parentName == "explorer" || parentName == "browser") && childName == "msbuild")
                report.Add(20, $"MSBuild spawned by '{parentName}' (unusual)");
        }

        // ---- Static file inspection primitives ----------------------------------

        static double FileEntropy(string path)
        {
            try
            {
                const int sampleCap = 4 * 1024 * 1024;
                var counts = new long[256];
                long total = 0;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buffer = new byte[64 * 1024];
                int read;
                while (total < sampleCap && (read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < read; i++) counts[buffer[i]]++;
                    total += read;
                }
                if (total == 0) return 0;

                double entropy = 0;
                for (int i = 0; i < 256; i++)
                {
                    if (counts[i] == 0) continue;
                    double p = (double)counts[i] / total;
                    entropy -= p * Math.Log(p, 2);
                }
                return entropy;
            }
            catch { return 0; }
        }

        // Reads the PE header and checks the CLR (COM descriptor) data directory.
        static bool IsDotNetAssembly(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var br = new BinaryReader(fs);
                if (fs.Length < 0x40) return false;

                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset > fs.Length - 4) return false;

                fs.Position = peOffset;
                if (br.ReadUInt32() != 0x00004550) return false; // "PE\0\0"

                fs.Position = peOffset + 4;
                ushort machine = br.ReadUInt16();
                fs.Position += 2; // NumberOfSections
                fs.Position += 12; // TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
                fs.Position += 2; // SizeOfOptionalHeader
                fs.Position += 2; // Characteristics

                ushort magic = br.ReadUInt16(); // optional header magic
                bool isPE32Plus = magic == 0x20B;
                // Data directories start after the optional header standard/windows fields.
                // COM descriptor is directory index 14.
                int dataDirOffset = peOffset + 24 + (isPE32Plus ? 112 : 96);
                fs.Position = dataDirOffset + 14 * 8;
                if (fs.Position + 8 > fs.Length) return false;
                uint comRva = br.ReadUInt32();
                uint comSize = br.ReadUInt32();
                return comRva != 0 && comSize != 0;
            }
            catch { return false; }
        }

        // Verify Authenticode signature and trust chain via WinVerifyTrust.
        static bool IsAuthenticodeTrusted(string path)
        {
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = path,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                IntPtr pData = IntPtr.Zero;
                try
                {
                    Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                    var data = new WINTRUST_DATA
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                        pPolicyCallbackData = IntPtr.Zero,
                        pSIPClientData = IntPtr.Zero,
                        dwUIChoice = WTD_UI_NONE,
                        fdwRevocationChecks = WTD_REVOKE_NONE,
                        dwUnionChoice = WTD_CHOICE_FILE,
                        pFile = pFileInfo,
                        dwStateAction = WTD_STATEACTION_VERIFY,
                        hWVTStateData = IntPtr.Zero,
                        pwszURLReference = null,
                        dwProvFlags = WTD_SAFER_FLAG,
                        dwUIContext = 0,
                        pSignatureSettings = IntPtr.Zero
                    };

                    pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                    Marshal.StructureToPtr(data, pData, false);

                    uint result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                    // Close the state handle.
                    data.dwStateAction = WTD_STATEACTION_CLOSE;
                    Marshal.StructureToPtr(data, pData, true);
                    WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                    return result == 0;
                }
                finally
                {
                    if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
                    Marshal.FreeHGlobal(pFileInfo);
                }
            }
            catch
            {
                // If the API is unavailable, don't penalise the file.
                return true;
            }
        }

        // Scans the file for ASCII and UTF-16LE occurrences of any signature.
        static int ScanForSignatures(string path, string[] signatures)
        {
            try
            {
                var info = new FileInfo(path);
                if (info.Length > 32 * 1024 * 1024) return 0; // skip huge files

                byte[] bytes = File.ReadAllBytes(path);
                string ascii = Encoding.ASCII.GetString(bytes);
                string unicode = Encoding.Unicode.GetString(bytes);

                int hits = 0;
                foreach (string sig in signatures)
                {
                    if (ascii.IndexOf(sig, StringComparison.Ordinal) >= 0 ||
                        unicode.IndexOf(sig, StringComparison.Ordinal) >= 0)
                        hits++;
                }
                return hits;
            }
            catch { return 0; }
        }

        // ---- Helpers -------------------------------------------------------------

        static string SafeMainModulePath(Process proc)
        {
            try { return proc.MainModule?.FileName ?? ""; }
            catch { return ""; }
        }

        public static bool LooksSuspiciousLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            foreach (string dir in SuspiciousDirs)
                if (lower.Contains(dir)) return true;
            return false;
        }

        public static bool IsTrustedSystemPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            return lower.StartsWith(@"c:\windows\system32\") ||
                   lower.StartsWith(@"c:\windows\syswow64\") ||
                   lower == @"c:\windows\explorer.exe" ||
                   lower.StartsWith(@"c:\program files\") ||
                   lower.StartsWith(@"c:\program files (x86)\");
        }

        static bool IsCriticalName(string lowerName)
        {
            return lowerName is "svchost" or "explorer" or "msbuild" or "lsass"
                or "csrss" or "winlogon" or "services" or "smss" or "wininit";
        }

        // ---- WMI process snapshot -----------------------------------------------

        // Returns a pid -> metadata map. Uses System.Management (WMI). Failures
        // are swallowed so the tool keeps working on locked-down systems.
        public static Dictionary<int, ProcessMeta> SnapshotProcesses()
        {
            var map = new Dictionary<int, ProcessMeta>();
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process");
                foreach (var o in searcher.Get())
                {
                    try
                    {
                        var meta = new ProcessMeta
                        {
                            Pid = ToInt(o["ProcessId"]),
                            ParentPid = ToInt(o["ParentProcessId"]),
                            Name = o["Name"]?.ToString() ?? "",
                            ExecutablePath = o["ExecutablePath"]?.ToString() ?? "",
                            CommandLine = o["CommandLine"]?.ToString() ?? ""
                        };
                        if (meta.Pid > 0) map[meta.Pid] = meta;
                    }
                    catch { }
                }
            }
            catch { /* WMI unavailable */ }
            return map;
        }

        static int ToInt(object? o)
        {
            try { return o == null ? 0 : Convert.ToInt32(o); }
            catch { return 0; }
        }

        // ---- WinVerifyTrust interop ---------------------------------------------

        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        const uint WTD_UI_NONE = 2;
        const uint WTD_REVOKE_NONE = 0;
        const uint WTD_CHOICE_FILE = 1;
        const uint WTD_STATEACTION_VERIFY = 1;
        const uint WTD_STATEACTION_CLOSE = 2;
        const uint WTD_SAFER_FLAG = 0x100;

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string? pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }
    }
}
