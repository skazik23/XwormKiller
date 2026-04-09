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
                            {
                                string value = key.GetValue(valueName)?.ToString().ToLower();
                                if (value != null)
                                {
                                    foreach (string bad in badKeywords)
                                    {
                                        if (value.Contains(bad))
                                        {
                                            key.DeleteValue(valueName);
                                            WriteColoredLine($"[+] Deleted autorun: {valueName} -> {value}");
                                            foundAnything = true;
                                            break;
                                        }
                                    }
                                }
                            }
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
                            {
                                string value = key.GetValue(valueName)?.ToString().ToLower();
                                if (value != null)
                                {
                                    foreach (string bad in badKeywords)
                                    {
                                        if (value.Contains(bad))
                                        {
                                            key.DeleteValue(valueName);
                                            WriteColoredLine($"[+] Deleted autorun (current user): {valueName} -> {value}");
                                            foundAnything = true;
                                            break;
                                        }
                                    }
                                }
                            }
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
            WriteColoredLine("[*] Scanning Task Scheduler...");
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "schtasks.exe";
                process.StartInfo.Arguments = "/query /fo csv /nh";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                string[] lines = output.Split('\n');
                string[] badTasks = { "worm", "rat", "xworm", "update", "java", "client", "server", "mscoree" };
                
                foreach (string line in lines)
                {
                    foreach (string bad in badTasks)
                    {
                        if (line.ToLower().Contains(bad))
                        {
                            string taskName = line.Split(',')[0].Replace("\"", "");
                            if (!string.IsNullOrEmpty(taskName) && taskName != "TaskName")
                            {
                                Process deleteTask = new Process();
                                deleteTask.StartInfo.FileName = "schtasks.exe";
                                deleteTask.StartInfo.Arguments = $"/delete /tn \"{taskName}\" /f";
                                deleteTask.StartInfo.CreateNoWindow = true;
                                deleteTask.Start();
                                deleteTask.WaitForExit();
                                WriteColoredLine($"[+] Deleted scheduled task: {taskName}");
                                foundAnything = true;
                            }
                            break;
                        }
                    }
                }
            }
            catch { }
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
            string[] badNames = { "worm", "rat", "client", "server", "xworm", "svhost", "winupdate", "mscoree" };
            
            Thread processMonitor = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        if (DateTime.Now - lastDeepAnalyze >= deepAnalyzeInterval)
                        {
                            AnalyzeSystemProcesses();
                            lastDeepAnalyze = DateTime.Now;
                        }
                        
                        foreach (var proc in Process.GetProcesses())
                        {
                            try
                            {
                                if (!seenPids.Contains(proc.Id))
                                {
                                    seenPids.Add(proc.Id);
                                    string name = proc.ProcessName.ToLower();
                                    foreach (string bad in badNames)
                                    {
                                        if (name.Contains(bad) && !IsSelfProcess(proc.Id, proc.ProcessName))
                                        {
                                            WriteColoredLine($"[ALERT] New malicious process detected: {proc.ProcessName} (PID: {proc.Id})");
                                            KillProcess(proc.Id, proc.ProcessName);
                                            break;
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
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
            Console.Title = "XwormKiller | tg: @cmspip";
            Console.WindowWidth = 130;
            Console.WindowHeight = 40;
            PrintBanner();
            
            RemoveAutoRun();
            CleanTaskScheduler();
            CleanCache();
            BlockRatPorts();
            AnalyzeSystemProcesses();
            FindAndFuckRatPorts();
            
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
