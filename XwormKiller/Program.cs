using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections.Generic;
using Microsoft.Win32;
using System.IO;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace WormKiller
{
    class Program
    {
        [DllImport("ntdll.dll")]
        static extern int NtSuspendProcess(IntPtr processHandle);
        
        [DllImport("user32.dll")]
        static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
        
        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        
        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);
        
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
        
        static bool foundAnything = false;
        static int currentPid = 0;
        static DateTime lastDeepAnalyze = DateTime.MinValue;
        static readonly TimeSpan deepAnalyzeInterval = TimeSpan.FromSeconds(30);

        static void WriteColoredLine(string text)
        {
            if (text.Contains("Deleted scheduled task:"))
            {
                int colonIndex = text.IndexOf(':');
                string prefix = text.Substring(0, colonIndex + 1);
                string path = text.Substring(colonIndex + 1).TrimStart();
                
                Console.ForegroundColor = ConsoleColor.Blue;
                int delIndex = prefix.IndexOf("Deleted");
                Console.Write(prefix.Substring(0, delIndex));
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("Deleted");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write(prefix.Substring(delIndex + 7));
                
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(" " + path);
                Console.ResetColor();
                return;
            }
            
            if (text.Contains("blocked"))
            {
                int blockedIndex = text.IndexOf("blocked");
                string before = text.Substring(0, blockedIndex);
                string after = text.Substring(blockedIndex + 7);
                
                PrintColoredSegment(before);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("blocked");
                Console.ForegroundColor = ConsoleColor.Blue;
                PrintColoredSegment(after);
                Console.WriteLine();
                Console.ResetColor();
                return;
            }
            
            PrintColoredSegment(text);
            Console.WriteLine();
        }

        static void PrintColoredSegment(string text)
        {
            string pattern = @"(\(|\)|\[|\]|\{|\})|(\+|\*|\-)|(Deleted)";
            var matches = Regex.Matches(text, pattern);
            int lastIndex = 0;
            foreach (Match m in matches)
            {
                string before = text.Substring(lastIndex, m.Index - lastIndex);
                if (before.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.Write(before);
                }
                if (m.Groups[1].Success)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.Write(m.Value);
                }
                else if (m.Groups[2].Success)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(m.Value);
                }
                else if (m.Groups[3].Success)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write(m.Value);
                }
                lastIndex = m.Index + m.Length;
            }
            if (lastIndex < text.Length)
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write(text.Substring(lastIndex));
            }
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
   _  __                                     __          __                  __  _           
  | |/ /      ______  _________ ___     ____/ /__  _____/ /________  _______/ /_(_)___  ____ 
  |   / | /| / / __ \/ ___/ __ `__ \   / __  / _ \/ ___/ __/ ___/ / / / ___/ __/ / __ \/ __ \
 /   || |/ |/ / /_/ / /  / / / / / /  / /_/ /  __(__  ) /_/ /  / /_/ / /__/ /_/ / /_/ / / / /
/_/|_||__/|__/\____/_/  /_/ /_/ /_/   \__,_/\___/____/\__/_/   \__,_/\___/\__/_/\____/_/ /_/ 
                                                                                             ");
            Console.ResetColor();
            Console.WriteLine();
            WriteColoredLine("[+] Analysis enabled!");
            WriteColoredLine("[-] I look at processes and other things.");
        }

        static bool IsSelfProcess(int pid, string processName)
        {
            if (pid == currentPid) return true;
            if (processName.Equals("XwormKiller", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static void KillProcess(int pid, string name)
        {
            if (IsSelfProcess(pid, name))
            {
                WriteColoredLine($"[!] Skipping self-process [{name}] (PID: {pid}) - cannot terminate itself");
                return;
            }
            try
            {
                Process p = Process.GetProcessById(pid);
                p.Kill();
                WriteColoredLine($"[+] The process [{name}] (PID: {pid}) has been found! I will liquidate it!!");
            }
            catch
            {
                try
                {
                    var handle = Process.GetProcessById(pid).Handle;
                    NtSuspendProcess(handle);
                    WriteColoredLine($"[!] The process [{name}] (PID: {pid}) suspended (could not terminate)");
                }
                catch
                {
                    WriteColoredLine($"[-] Failed to touch process [{name}] (PID: {pid})");
                }
            }
        }

        static int GetParentProcessId(int pid)
        {
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == IntPtr.Zero) return 0;
            
            PROCESSENTRY32 pe = new PROCESSENTRY32();
            pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
            
            if (Process32First(hSnapshot, ref pe))
            {
                do
                {
                    if (pe.th32ProcessID == pid)
                    {
                        CloseHandle(hSnapshot);
                        return (int)pe.th32ParentProcessID;
                    }
                } while (Process32Next(hSnapshot, ref pe));
            }
            CloseHandle(hSnapshot);
            return 0;
        }

        static void AnalyzeSystemProcesses()
        {
            WriteColoredLine("[*] Deep analyzing critical system processes for RAT injection...");
            string[] criticalProcs = { "svchost", "explorer", "msbuild" };
            string[] trustedPaths = {
                @"C:\Windows\System32\",
                @"C:\Windows\SysWOW64\",
                @"C:\Windows\explorer.exe"
            };
            
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLower();
                    bool isCritical = false;
                    foreach (string crit in criticalProcs)
                    {
                        if (name == crit.ToLower())
                        {
                            isCritical = true;
                            break;
                        }
                    }
                    if (!isCritical) continue;
                    
                    string filePath = proc.MainModule.FileName;
                    bool pathValid = false;
                    foreach (string trusted in trustedPaths)
                    {
                        if (filePath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                        {
                            pathValid = true;
                            break;
                        }
                    }
                    if (!pathValid)
                    {
                        WriteColoredLine($"[!!!] CRITICAL: {proc.ProcessName} running from fake location: {filePath}");
                        KillProcess(proc.Id, proc.ProcessName);
                        foundAnything = true;
                        continue;
                    }
                    
                    bool injected = false;
                    try
                    {
                        foreach (ProcessModule module in proc.Modules)
                        {
                            string modPath = module.FileName.ToLower();
                            if (modPath.Contains("\\temp\\") || modPath.Contains("\\appdata\\") || 
                                modPath.Contains("\\downloads\\") || modPath.Contains("\\desktop\\"))
                            {
                                WriteColoredLine($"[!!!] Suspicious DLL injected into {proc.ProcessName}: {module.FileName}");
                                KillProcess(proc.Id, proc.ProcessName);
                                injected = true;
                                foundAnything = true;
                                break;
                            }
                        }
                    }
                    catch { }
                    if (injected) continue;
                    
                    if (name == "explorer")
                    {
                        int parentPid = GetParentProcessId(proc.Id);
                        if (parentPid > 0)
                        {
                            try
                            {
                                Process parent = Process.GetProcessById(parentPid);
                                if (!parent.ProcessName.Equals("winlogon", StringComparison.OrdinalIgnoreCase) &&
                                    !parent.ProcessName.Equals("userinit", StringComparison.OrdinalIgnoreCase))
                                {
                                    WriteColoredLine($"[WARNING] Explorer.exe started by unexpected parent: {parent.ProcessName} (PID: {parent.Id}) -> possible RAT, but not killed automatically");
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }

        // Acts on a weighted verdict: kill on Malicious, warn on Suspicious,
        // quietly log low-confidence signals. This replaces the old "name
        // contains a bad word -> kill" logic that endangered clean software.
        static void HandleThreat(ThreatReport report, int pid, string name)
        {
            switch (report.Level)
            {
                case ThreatLevel.Malicious:
                    WriteColoredLine($"[!!!] MALICIOUS: {report.Target} score={report.Score}");
                    foreach (string r in report.Reasons) WriteColoredLine($"      - {r}");
                    if (pid > 0) KillProcess(pid, name);
                    foundAnything = true;
                    break;
                case ThreatLevel.Suspicious:
                    WriteColoredLine($"[WARNING] SUSPICIOUS (not killed): {report.Target} score={report.Score}");
                    foreach (string r in report.Reasons) WriteColoredLine($"      - {r}");
                    foundAnything = true;
                    break;
                case ThreatLevel.Low:
                    WriteColoredLine($"[i] Low-confidence signal on {report.Target} (score={report.Score})");
                    break;
            }
        }

        // Deep scan every running process: static file analysis + runtime
        // signals + command-line + process-tree, scored per process.
        static void DeepScanAllProcesses()
        {
            WriteColoredLine("[*] Deep-scanning all running processes (signatures, signature-check, entropy, injection)...");
            Dictionary<int, ProcessMeta> meta = ThreatAnalyzer.SnapshotProcesses();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (IsSelfProcess(proc.Id, proc.ProcessName)) continue;
                    meta.TryGetValue(proc.Id, out ProcessMeta? pm);
                    ThreatReport report = ThreatAnalyzer.AnalyzeProcess(proc, pm);
                    HandleThreat(report, proc.Id, proc.ProcessName);
                }
                catch { }
            }
        }

        // Analyze live network connections. Established links to routable
        // remote hosts on known RAT ports are strong C2 evidence; we score
        // the owning process rather than blindly killing by port number.
        static void AnalyzeNetworkConnections()
        {
            WriteColoredLine("[*] Analyzing active network connections for C2 channels...");
            List<NetConnection> conns = NetworkInspector.GetConnections();
            Dictionary<int, ProcessMeta> meta = ThreatAnalyzer.SnapshotProcesses();

            foreach (var c in conns)
            {
                if (c.Protocol != "TCP") continue;

                bool established = c.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase);
                bool listeningRat = c.State.Equals("LISTENING", StringComparison.OrdinalIgnoreCase) &&
                                    NetworkInspector.IsRatPort(c.LocalPort);
                bool c2Link = established && NetworkInspector.IsRatPort(c.RemotePort) &&
                              NetworkInspector.IsRoutableRemote(c.RemoteAddress);

                if (!listeningRat && !c2Link) continue;
                if (c.Pid <= 0 || IsSelfProcessPid(c.Pid)) continue;

                Process proc;
                try { proc = Process.GetProcessById(c.Pid); }
                catch { continue; }

                var report = ThreatAnalyzer.AnalyzeProcess(proc, meta.TryGetValue(c.Pid, out var pm) ? pm : null);

                if (c2Link)
                {
                    report.Add(50, $"ESTABLISHED C2 link to {c.RemoteAddress}:{c.RemotePort}");
                    WriteColoredLine($"[!!!] Active C2 channel: {proc.ProcessName} (PID {c.Pid}) -> {c.RemoteAddress}:{c.RemotePort}");
                }
                if (listeningRat)
                    report.Add(25, $"listening on RAT port {c.LocalPort}");

                HandleThreat(report, c.Pid, proc.ProcessName);
            }
        }

        static bool IsSelfProcessPid(int pid)
        {
            if (pid == currentPid) return true;
            try { return IsSelfProcess(pid, Process.GetProcessById(pid).ProcessName); }
            catch { return false; }
        }

        static bool ProcessStillAlive(int pid)
        {
            try { Process.GetProcessById(pid); return true; }
            catch { return false; }
        }

        // Detects Image File Execution Options debugger hijacks - a stealth
        // persistence/defense-evasion trick that points a legit binary at a RAT.
        static void AnalyzeIfeoHijacks()
        {
            WriteColoredLine("[*] Checking Image File Execution Options for debugger hijacks...");
            const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using RegistryKey? root = Registry.LocalMachine.OpenSubKey(ifeo, true);
                if (root == null) return;
                foreach (string sub in root.GetSubKeyNames())
                {
                    try
                    {
                        using RegistryKey? k = root.OpenSubKey(sub, true);
                        string? dbg = k?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrEmpty(dbg))
                        {
                            string lower = dbg.ToLowerInvariant();
                            // A legitimate debugger lives in system dirs; RAT
                            // hijacks point at temp/appdata or a scripting host.
                            if (ThreatAnalyzer.LooksSuspiciousLocation(lower) ||
                                lower.Contains("powershell") || lower.Contains("cmd") ||
                                lower.Contains("mshta") || lower.Contains("wscript"))
                            {
                                WriteColoredLine($"[!!!] IFEO debugger hijack on '{sub}' -> {dbg}");
                                k?.DeleteValue("Debugger");
                                foundAnything = true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        static readonly string[] AutorunBadKeywords =
            { "worm", "rat", "xworm", "svhost", "winupdate", "mscoree" };

        // Extracts the executable path from an autorun/command-line value.
        static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return "";
            string s = commandLine.Trim();
            if (s.StartsWith("\""))
            {
                int end = s.IndexOf('"', 1);
                if (end > 1) return s.Substring(1, end - 1);
            }
            int space = s.IndexOf(' ');
            return space > 0 ? s.Substring(0, space) : s;
        }

        // Inspects one autorun value: keyword match first, then deep static
        // analysis of the referenced binary so benign-looking entries that
        // point at a real payload are still caught. Returns true if removed.
        static bool InspectAndCleanAutorun(RegistryKey key, string valueName, string scope)
        {
            string? raw = key.GetValue(valueName)?.ToString();
            if (string.IsNullOrEmpty(raw)) return false;
            string lower = raw.ToLowerInvariant();

            foreach (string bad in AutorunBadKeywords)
            {
                if (lower.Contains(bad))
                {
                    try { key.DeleteValue(valueName); } catch { }
                    WriteColoredLine($"[+] Deleted autorun{scope}: {valueName} -> {raw}");
                    foundAnything = true;
                    return true;
                }
            }

            string path = ExtractExecutablePath(raw);
            if (!string.IsNullOrEmpty(path))
            {
                ThreatReport report = ThreatAnalyzer.AnalyzeFile(path);
                if (report.Level >= ThreatLevel.Suspicious)
                {
                    WriteColoredLine($"[!!!] Malicious autorun target{scope}: {valueName} -> {raw} (score={report.Score})");
                    foreach (string r in report.Reasons) WriteColoredLine($"      - {r}");
                    foundAnything = true;
                    if (report.Level == ThreatLevel.Malicious)
                    {
                        try { key.DeleteValue(valueName); } catch { }
                        WriteColoredLine($"[+] Deleted autorun{scope}: {valueName}");
                        return true;
                    }
                }
            }
            return false;
        }

        static void RemoveAutoRun()
        {
            WriteColoredLine("[*] Cleaning autorun registry...");
            string[] runPaths = {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
            };
            
            string[] badKeywords = { "worm", "rat", "client", "server", "xworm", "svhost", "winupdate", "mscoree" };
            
            foreach (string path in runPaths)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path, true))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                                InspectAndCleanAutorun(key, valueName, "");
                        }
                    }
                }
                catch { }
                
                string userPath = path.Replace("SOFTWARE\\", "");
                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(userPath, true))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                                InspectAndCleanAutorun(key, valueName, " (current user)");
                        }
                    }
                }
                catch { }
            }
            
            string startupPaths = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            string startupCommon = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            
            foreach (string file in Directory.GetFiles(startupPaths))
            {
                foreach (string bad in badKeywords)
                {
                    if (file.ToLower().Contains(bad))
                    {
                        File.Delete(file);
                        WriteColoredLine($"[+] Deleted from startup: {file}");
                        foundAnything = true;
                        break;
                    }
                }
            }
            
            foreach (string file in Directory.GetFiles(startupCommon))
            {
                foreach (string bad in badKeywords)
                {
                    if (file.ToLower().Contains(bad))
                    {
                        File.Delete(file);
                        WriteColoredLine($"[+] Deleted from common startup: {file}");
                        foundAnything = true;
                        break;
                    }
                }
            }
        }

        static void CleanTaskScheduler()
        {
            WriteColoredLine("[*] Scanning Task Scheduler (name + action target analysis)...");
            try
            {
                // Verbose list output exposes "Task To Run", the actual command
                // a task executes - so we can analyze the referenced binary
                // instead of guessing from the task name alone.
                Process process = new Process();
                process.StartInfo.FileName = "schtasks.exe";
                process.StartInfo.Arguments = "/query /v /fo list";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // High-signal name keywords only - dropped the FP-prone
                // "update"/"java"/"client"/"server" that matched Windows tasks.
                string[] badNameKeywords = { "worm", "rat", "xworm", "mscoree", "svhost" };

                string currentTaskName = "";
                string currentTaskToRun = "";

                foreach (string raw in output.Split('\n'))
                {
                    string line = raw.TrimEnd('\r');
                    if (line.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase))
                    {
                        // New task block: evaluate the previous one first.
                        EvaluateScheduledTask(currentTaskName, currentTaskToRun, badNameKeywords);
                        currentTaskName = line.Substring("TaskName:".Length).Trim();
                        currentTaskToRun = "";
                    }
                    else if (line.StartsWith("Task To Run:", StringComparison.OrdinalIgnoreCase))
                    {
                        currentTaskToRun = line.Substring("Task To Run:".Length).Trim();
                    }
                }
                EvaluateScheduledTask(currentTaskName, currentTaskToRun, badNameKeywords);
            }
            catch { }
        }

        static void EvaluateScheduledTask(string taskName, string taskToRun, string[] badNameKeywords)
        {
            if (string.IsNullOrEmpty(taskName)) return;

            string haystack = (taskName + " " + taskToRun).ToLowerInvariant();
            bool malicious = false;
            string why = "";

            foreach (string bad in badNameKeywords)
            {
                if (haystack.Contains(bad)) { malicious = true; why = $"name/command matches '{bad}'"; break; }
            }

            // Deep: analyze the binary the task actually launches.
            if (!malicious && !string.IsNullOrEmpty(taskToRun))
            {
                string path = ExtractExecutablePath(taskToRun);
                if (!string.IsNullOrEmpty(path))
                {
                    ThreatReport report = ThreatAnalyzer.AnalyzeFile(path);
                    if (report.Level == ThreatLevel.Malicious)
                    {
                        malicious = true;
                        why = $"action target scored {report.Score}";
                    }
                    else if (report.Level == ThreatLevel.Suspicious)
                    {
                        WriteColoredLine($"[WARNING] Suspicious scheduled task (not deleted): {taskName} -> {taskToRun} (score={report.Score})");
                        foundAnything = true;
                    }
                }
            }

            if (malicious)
            {
                try
                {
                    Process deleteTask = new Process();
                    deleteTask.StartInfo.FileName = "schtasks.exe";
                    deleteTask.StartInfo.Arguments = $"/delete /tn \"{taskName}\" /f";
                    deleteTask.StartInfo.CreateNoWindow = true;
                    deleteTask.Start();
                    deleteTask.WaitForExit();
                }
                catch { }
                WriteColoredLine($"[+] Deleted scheduled task: {taskName} ({why})");
                foundAnything = true;
            }
        }

        static void CleanCache()
        {
            WriteColoredLine("[*] Cleaning system cache...");
            string[] pathsToClean = {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.InternetCache),
                Environment.GetFolderPath(Environment.SpecialFolder.History),
                Environment.GetFolderPath(Environment.SpecialFolder.Cookies),
                @"C:\Windows\Prefetch",
                @"C:\Windows\Temp",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };
            
            foreach (string path in pathsToClean)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        foreach (string file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
                        {
                            try
                            {
                                string fileName = file.ToLower();
                                if (fileName.Contains("worm") || fileName.Contains("rat") || 
                                    fileName.Contains("xworm") || fileName.Contains("client") ||
                                    fileName.Contains("server"))
                                {
                                    File.Delete(file);
                                    WriteColoredLine($"[+] Deleted cache file: {file}");
                                    foundAnything = true;
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
            
            try
            {
                Process.Start(new ProcessStartInfo("cmd.exe", "/c rd /s /q C:\\$Recycle.Bin 2>nul") { CreateNoWindow = true, UseShellExecute = false }).WaitForExit();
                WriteColoredLine("[+] Recycled bin cleaned");
            }
            catch { }
        }

        static void BlockRatPorts()
        {
            WriteColoredLine("[*] Blocking RAT ports via Windows Firewall...");
            int[] ratPorts = { 1337, 4444, 5555, 6666, 7777, 8888, 9999, 8080, 1604, 3306, 3389, 5900, 54321, 31337 };
            
            foreach (int port in ratPorts)
            {
                try
                {
                    Process remove = new Process();
                    remove.StartInfo.FileName = "netsh.exe";
                    remove.StartInfo.Arguments = $"advfirewall firewall delete rule name=\"Block_RAT_Port_{port}\"";
                    remove.StartInfo.CreateNoWindow = true;
                    remove.Start();
                    remove.WaitForExit();
                }
                catch { }
                
                try
                {
                    Process process = new Process();
                    process.StartInfo.FileName = "netsh.exe";
                    process.StartInfo.Arguments = $"advfirewall firewall add rule name=\"Block_RAT_Port_{port}\" dir=in action=block protocol=tcp localport={port}";
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.UseShellExecute = false;
                    process.Start();
                    process.WaitForExit();
                    WriteColoredLine($"[+] Port {port} blocked (inbound)");
                    
                    Process processOut = new Process();
                    processOut.StartInfo.FileName = "netsh.exe";
                    processOut.StartInfo.Arguments = $"advfirewall firewall add rule name=\"Block_RAT_Port_{port}_out\" dir=out action=block protocol=tcp localport={port}";
                    processOut.StartInfo.CreateNoWindow = true;
                    processOut.StartInfo.UseShellExecute = false;
                    processOut.Start();
                    processOut.WaitForExit();
                    WriteColoredLine($"[+] Port {port} blocked (outbound)");
                }
                catch { }
            }
        }

        static void FindAndFuckRatPorts()
        {
            WriteColoredLine("[*] Scanning for active RAT ports and fucking them...");
            int[] ratPorts = { 1337, 4444, 5555, 6666, 7777, 8888, 9999, 8080, 1604, 3306, 3389, 5900, 54321, 31337, 50000, 50001 };
            
            foreach (int port in ratPorts)
            {
                TcpClient client = null;
                try
                {
                    client = new TcpClient();
                    IAsyncResult result = client.BeginConnect("127.0.0.1", port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(100, false);
                    if (success)
                    {
                        client.EndConnect(result);
                        WriteColoredLine($"[!!!] ACTIVE PORT DETECTED: {port}");
                        foundAnything = true;
                        
                        Process netstat = new Process();
                        netstat.StartInfo.FileName = "netstat.exe";
                        netstat.StartInfo.Arguments = "-ano -p tcp";
                        netstat.StartInfo.UseShellExecute = false;
                        netstat.StartInfo.RedirectStandardOutput = true;
                        netstat.StartInfo.CreateNoWindow = true;
                        netstat.Start();
                        string output = netstat.StandardOutput.ReadToEnd();
                        netstat.WaitForExit();
                        
                        string[] lines = output.Split('\n');
                        foreach (string line in lines)
                        {
                            if (line.Contains($":{port}") && line.Contains("LISTENING"))
                            {
                                string[] parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 5)
                                {
                                    int pid = int.Parse(parts[4]);
                                    try
                                    {
                                        Process badProc = Process.GetProcessById(pid);
                                        KillProcess(pid, badProc.ProcessName);
                                        WriteColoredLine($"[!!!] FUCKED process {badProc.ProcessName} on port {port}");
                                        
                                        try
                                        {
                                            TcpClient fucker = new TcpClient();
                                            fucker.Connect("127.0.0.1", port);
                                            byte[] junk = new byte[65535];
                                            new Random().NextBytes(junk);
                                            fucker.GetStream().Write(junk, 0, junk.Length);
                                            fucker.Close();
                                            WriteColoredLine($"[!!!] Port {port} flooded with junk data");
                                        }
                                        catch { }
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
                catch { }
                finally
                {
                    client?.Close();
                }
            }
        }

        static void MonitorProcessesAndPorts()
        {
            HashSet<int> seenPids = new HashSet<int>();

            Thread processMonitor = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        // Periodic full deep sweep: every process re-scored plus
                        // live network connection analysis for C2 channels.
                        if (DateTime.Now - lastDeepAnalyze >= deepAnalyzeInterval)
                        {
                            AnalyzeSystemProcesses();
                            DeepScanAllProcesses();
                            AnalyzeNetworkConnections();
                            AnalyzeIfeoHijacks();
                            lastDeepAnalyze = DateTime.Now;
                        }

                        // Fast path: fully analyze only freshly-appeared processes
                        // so newly-launched payloads are caught within ~1 second.
                        var newProcs = new List<Process>();
                        foreach (var proc in Process.GetProcesses())
                        {
                            try
                            {
                                if (seenPids.Add(proc.Id) && !IsSelfProcess(proc.Id, proc.ProcessName))
                                    newProcs.Add(proc);
                            }
                            catch { }
                        }

                        if (newProcs.Count > 0)
                        {
                            Dictionary<int, ProcessMeta> meta = ThreatAnalyzer.SnapshotProcesses();
                            foreach (var proc in newProcs)
                            {
                                try
                                {
                                    meta.TryGetValue(proc.Id, out ProcessMeta? pm);
                                    ThreatReport report = ThreatAnalyzer.AnalyzeProcess(proc, pm);
                                    if (report.Level >= ThreatLevel.Low)
                                        HandleThreat(report, proc.Id, proc.ProcessName);
                                }
                                catch { }
                            }
                        }

                        // Forget dead PIDs so a recycled PID gets re-analyzed.
                        seenPids.RemoveWhere(pid => !ProcessStillAlive(pid));

                        Thread.Sleep(1000);
                    }
                    catch { }
                }
            });
            processMonitor.IsBackground = true;
            processMonitor.Start();

            int[] ratPorts = { 1337, 4444, 5555, 6666, 7777, 8888, 9999, 8080, 1604, 3306, 3389, 5900, 54321, 31337, 50000, 50001 };
            Thread portMonitor = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        foreach (int port in ratPorts)
                        {
                            TcpClient check = null;
                            try
                            {
                                check = new TcpClient();
                                if (check.ConnectAsync("127.0.0.1", port).Wait(50))
                                {
                                    WriteColoredLine($"[ALERT] New connection on port {port} - FUCKING IT");
                                    check.Close();
                                    
                                    Process find = new Process();
                                    find.StartInfo.FileName = "cmd.exe";
                                    find.StartInfo.Arguments = $"/c for /f \"tokens=5\" %a in ('netstat -ano ^| findstr :{port}') do taskkill /f /pid %a";
                                    find.StartInfo.CreateNoWindow = true;
                                    find.Start();
                                }
                            }
                            catch { }
                            finally
                            {
                                check?.Close();
                            }
                        }
                        Thread.Sleep(2000);
                    }
                    catch { }
                }
            });
            portMonitor.IsBackground = true;
            portMonitor.Start();
        }

        static void ClearAndShowStatus()
        {
            Console.Clear();
            PrintBanner();
            Console.WriteLine();
            WriteColoredLine("I'm watching the PC, don't worry.");
        }

        static void Main(string[] args)
        {
            currentPid = Process.GetCurrentProcess().Id;
            Console.Title = "XwormKiller | telegram: @xeocoder";
            Console.WindowWidth = 130;
            Console.WindowHeight = 40;
            PrintBanner();
            
            RemoveAutoRun();
            AnalyzeIfeoHijacks();
            CleanTaskScheduler();
            CleanCache();
            BlockRatPorts();
            AnalyzeSystemProcesses();
            DeepScanAllProcesses();
            AnalyzeNetworkConnections();
            FindAndFuckRatPorts();
            
            if (!foundAnything)
            {
                // Primary analysis found no trace of where the RAT hides -
                // instantly engage the custom Deep Protection hunter (5-10s).
                bool deepFound = DeepProtection.Engage(
                    TimeSpan.FromSeconds(8), currentPid, WriteColoredLine, KillProcess);
                if (deepFound) foundAnything = true;
            }

            if (!foundAnything)
            {
                WriteColoredLine("Oh... Thank God you're clean, relax.");
                Thread.Sleep(2000);
            }
            else
            {
                Thread.Sleep(3000);
            }

            ClearAndShowStatus();
            MonitorProcessesAndPorts();
            
            while (true)
            {
                Thread.Sleep(10000);
            }
        }
    }
}
