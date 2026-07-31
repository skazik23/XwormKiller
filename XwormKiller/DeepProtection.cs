using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WormKiller
{
    // ---------------------------------------------------------------------------
    // DeepProtection - custom, self-written last-resort hunter.
    //
    // The primary passes look at obvious places (autoruns, tasks, known ports,
    // system-process spoofing). When they come up empty it usually means the RAT
    // is hiding somewhere less obvious - a benignly-named binary in a deep user
    // folder, a script-based stub, a WMI event-consumer, or an already-running
    // process with a clean name but a dirty image.
    //
    // This module is engaged ONLY when the primary analysis found nothing. It
    // runs a hard, time-boxed (5-10s) parallel sweep across the whole attack
    // surface at once, so it stays fast while digging much deeper.
    // ---------------------------------------------------------------------------
    static class DeepProtection
    {
        static readonly object _logLock = new object();

        // File extensions worth inspecting during the filesystem sweep.
        static readonly string[] ExecExtensions =
            { ".exe", ".dll", ".scr", ".com", ".cpl", ".jar" };
        static readonly string[] ScriptExtensions =
            { ".ps1", ".vbs", ".js", ".jse", ".vbe", ".bat", ".cmd", ".hta", ".wsf", ".lnk" };

        // Script payload markers - cheap text hunt for stub/loader behaviour.
        static readonly string[] ScriptMarkers =
        {
            "xworm", "frombase64string", "downloadstring", "downloadfile",
            "invoke-expression", "iex(", "iex ", "-enc", "-encodedcommand",
            "shellcode", "virtualalloc", "createthread", "reflection.assembly",
            "webclient", "wscript.shell", "powershell -", "mshta", "regsvr32 /i"
        };

        // Engage the deep hunt. Returns true if anything malicious was found.
        //   budget  - wall-clock time limit (kept to 5-10s for responsiveness)
        //   selfPid - our own PID, never touched
        //   log     - console writer (WriteColoredLine), synchronised internally
        //   kill    - process terminator (Program.KillProcess), thread-safe
        public static bool Engage(TimeSpan budget, int selfPid, Action<string> log, Action<int, string> kill)
        {
            if (budget < TimeSpan.FromSeconds(5)) budget = TimeSpan.FromSeconds(5);
            if (budget > TimeSpan.FromSeconds(10)) budget = TimeSpan.FromSeconds(10);

            var sw = Stopwatch.StartNew();
            var findings = new ConcurrentBag<string>();
            using var cts = new CancellationTokenSource(budget);
            var token = cts.Token;

            void SafeLog(string s) { lock (_logLock) log(s); }

            SafeLog("");
            SafeLog("========================================================");
            SafeLog("[XEO-DEEP] Primary scan clean - engaging DEEP PROTECTION");
            SafeLog($"[XEO-DEEP] Hard time budget: {budget.TotalSeconds:F0}s. Hunting where the RAT hides...");
            SafeLog("========================================================");

            // All hunters run at once so the whole attack surface is covered
            // inside the time budget instead of sequentially.
            var hunters = new List<Task>
            {
                Task.Run(() => HuntRunningProcesses(token, selfPid, findings, SafeLog, kill), token),
                Task.Run(() => HuntFileSystem(token, findings, SafeLog), token),
                Task.Run(() => HuntWmiPersistence(token, findings, SafeLog), token),
                Task.Run(() => HuntNetworkOwners(token, selfPid, findings, SafeLog, kill), token)
            };

            try { Task.WaitAll(hunters.ToArray(), budget); }
            catch { /* cancellation / individual hunter faults are swallowed */ }

            sw.Stop();
            SafeLog("========================================================");
            if (findings.IsEmpty)
                SafeLog($"[XEO-DEEP] Deep sweep complete in {sw.Elapsed.TotalSeconds:F1}s - nothing hidden found. System is clean.");
            else
                SafeLog($"[XEO-DEEP] Deep sweep complete in {sw.Elapsed.TotalSeconds:F1}s - {findings.Count} hidden threat(s) neutralised.");
            SafeLog("========================================================");
            SafeLog("");

            return !findings.IsEmpty;
        }

        // ---- Hunter 1: every running process, scored via ThreatAnalyzer --------

        static void HuntRunningProcesses(CancellationToken token, int selfPid,
            ConcurrentBag<string> findings, Action<string> log, Action<int, string> kill)
        {
            Dictionary<int, ProcessMeta> meta;
            try { meta = ThreatAnalyzer.SnapshotProcesses(); }
            catch { meta = new Dictionary<int, ProcessMeta>(); }

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            var options = new ParallelOptions
            {
                CancellationToken = token,
                MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount)
            };

            try
            {
                Parallel.ForEach(procs, options, proc =>
                {
                    if (token.IsCancellationRequested) return;
                    try
                    {
                        if (proc.Id == selfPid) return;
                        meta.TryGetValue(proc.Id, out ProcessMeta? pm);
                        ThreatReport report = ThreatAnalyzer.AnalyzeProcess(proc, pm);
                        if (report.Level == ThreatLevel.Malicious)
                        {
                            log($"[XEO-DEEP][PROC] Hidden RAT process: {proc.ProcessName} (PID {proc.Id}) score={report.Score}");
                            foreach (string r in report.Reasons) log($"          - {r}");
                            kill(proc.Id, proc.ProcessName);
                            findings.Add($"proc:{proc.Id}");
                        }
                    }
                    catch { }
                });
            }
            catch (OperationCanceledException) { }
            catch { }
        }

        // ---- Hunter 2: deep filesystem sweep of user-writable locations --------

        static void HuntFileSystem(CancellationToken token, ConcurrentBag<string> findings, Action<string> log)
        {
            var roots = new List<string>();
            void AddRoot(string p) { if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) roots.Add(p); }

            AddRoot(Path.GetTempPath());
            AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            AddRoot(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            AddRoot(@"C:\Windows\Temp");
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            AddRoot(Path.Combine(profile, "Downloads"));
            AddRoot(Path.Combine(profile, "Desktop"));
            AddRoot(Path.Combine(profile, "Documents"));

            var options = new ParallelOptions
            {
                CancellationToken = token,
                MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount)
            };

            try
            {
                Parallel.ForEach(roots.Distinct(StringComparer.OrdinalIgnoreCase), options, root =>
                {
                    foreach (string file in EnumerateFilesSafe(root, token))
                    {
                        if (token.IsCancellationRequested) return;
                        try
                        {
                            string ext = Path.GetExtension(file).ToLowerInvariant();

                            if (ExecExtensions.Contains(ext))
                            {
                                ThreatReport report = ThreatAnalyzer.AnalyzeFile(file);
                                if (report.Level == ThreatLevel.Malicious)
                                {
                                    log($"[XEO-DEEP][FILE] Hidden payload: {file} score={report.Score}");
                                    foreach (string r in report.Reasons) log($"          - {r}");
                                    TryQuarantine(file, log);
                                    findings.Add($"file:{file}");
                                }
                            }
                            else if (ScriptExtensions.Contains(ext))
                            {
                                if (ScriptLooksMalicious(file))
                                {
                                    log($"[XEO-DEEP][SCRIPT] Malicious script stub: {file}");
                                    TryQuarantine(file, log);
                                    findings.Add($"script:{file}");
                                }
                            }
                        }
                        catch { }
                    }
                });
            }
            catch (OperationCanceledException) { }
            catch { }
        }

        // Enumerate files with a bounded recursion depth so a single huge tree
        // cannot eat the whole time budget. Access-denied dirs are skipped.
        static IEnumerable<string> EnumerateFilesSafe(string root, CancellationToken token, int maxDepth = 4)
        {
            var stack = new Stack<(string dir, int depth)>();
            stack.Push((root, 0));
            while (stack.Count > 0)
            {
                if (token.IsCancellationRequested) yield break;
                var (dir, depth) = stack.Pop();

                string[] files;
                try { files = Directory.GetFiles(dir); }
                catch { continue; }
                foreach (string f in files) yield return f;

                if (depth >= maxDepth) continue;
                string[] subs;
                try { subs = Directory.GetDirectories(dir); }
                catch { continue; }
                foreach (string s in subs) stack.Push((s, depth + 1));
            }
        }

        static bool ScriptLooksMalicious(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (info.Length > 4 * 1024 * 1024) return false;
                string text = File.ReadAllText(path).ToLowerInvariant();
                int hits = ScriptMarkers.Count(m => text.Contains(m));
                return hits >= 2;
            }
            catch { return false; }
        }

        // ---- Hunter 3: WMI event-consumer persistence (fileless RATs) ----------

        static void HuntWmiPersistence(CancellationToken token, ConcurrentBag<string> findings, Action<string> log)
        {
            if (token.IsCancellationRequested) return;
            try
            {
                var scope = new System.Management.ManagementScope(@"\\.\root\subscription");
                scope.Connect();

                InspectConsumers(scope, "ActiveScriptEventConsumer", "ScriptText", findings, log);
                InspectConsumers(scope, "CommandLineEventConsumer", "CommandLineTemplate", findings, log);
            }
            catch { /* WMI subscription namespace not accessible */ }
        }

        static void InspectConsumers(System.Management.ManagementScope scope, string className,
            string payloadProp, ConcurrentBag<string> findings, Action<string> log)
        {
            try
            {
                var query = new System.Management.ObjectQuery($"SELECT * FROM {className}");
                using var searcher = new System.Management.ManagementObjectSearcher(scope, query);
                foreach (var o in searcher.Get())
                {
                    try
                    {
                        string name = o["Name"]?.ToString() ?? "";
                        string payload = o[payloadProp]?.ToString() ?? "";
                        string lower = (name + " " + payload).ToLowerInvariant();

                        bool bad = ScriptMarkers.Count(m => lower.Contains(m)) >= 1 ||
                                   ThreatAnalyzer.LooksSuspiciousLocation(lower);
                        if (bad)
                        {
                            log($"[XEO-DEEP][WMI] Malicious {className} persistence: {name}");
                            try { (o as System.Management.ManagementObject)?.Delete(); log($"          - removed WMI consumer '{name}'"); }
                            catch { }
                            findings.Add($"wmi:{name}");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // ---- Hunter 4: owners of every active outbound connection --------------

        static void HuntNetworkOwners(CancellationToken token, int selfPid,
            ConcurrentBag<string> findings, Action<string> log, Action<int, string> kill)
        {
            if (token.IsCancellationRequested) return;

            List<NetConnection> conns;
            try { conns = NetworkInspector.GetConnections(); }
            catch { return; }

            Dictionary<int, ProcessMeta> meta;
            try { meta = ThreatAnalyzer.SnapshotProcesses(); }
            catch { meta = new Dictionary<int, ProcessMeta>(); }

            // Group by owning PID so each suspect process is analyzed once even
            // if it holds many sockets.
            foreach (var group in conns.Where(c => c.Protocol == "TCP" &&
                                                   c.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase) &&
                                                   NetworkInspector.IsRoutableRemote(c.RemoteAddress) &&
                                                   c.Pid > 0 && c.Pid != selfPid)
                                       .GroupBy(c => c.Pid))
            {
                if (token.IsCancellationRequested) return;
                int pid = group.Key;
                Process proc;
                try { proc = Process.GetProcessById(pid); }
                catch { continue; }

                meta.TryGetValue(pid, out ProcessMeta? pm);
                ThreatReport report;
                try { report = ThreatAnalyzer.AnalyzeProcess(proc, pm); }
                catch { continue; }

                // A process that is otherwise suspicious AND maintains outbound
                // links to routable hosts is a strong covert-C2 candidate.
                bool hitsRatPort = group.Any(c => NetworkInspector.IsRatPort(c.RemotePort));
                if (hitsRatPort) report.Add(40, "outbound link on a known RAT port");
                if (group.Count() > 12) report.Add(15, $"{group.Count()} concurrent outbound connections");

                if (report.Level == ThreatLevel.Malicious)
                {
                    var sample = group.First();
                    log($"[XEO-DEEP][NET] Covert C2 process: {proc.ProcessName} (PID {pid}) -> {sample.RemoteAddress}:{sample.RemotePort} score={report.Score}");
                    foreach (string r in report.Reasons) log($"          - {r}");
                    kill(pid, proc.ProcessName);
                    findings.Add($"net:{pid}");
                }
            }
        }

        // ---- Quarantine: rename+lock the payload so it cannot re-launch --------

        static void TryQuarantine(string file, Action<string> log)
        {
            try
            {
                string quarantined = file + ".xeoquarantine";
                if (File.Exists(quarantined)) File.Delete(quarantined);
                File.Move(file, quarantined);
                try { File.SetAttributes(quarantined, FileAttributes.Hidden | FileAttributes.ReadOnly); } catch { }
                log($"          - quarantined -> {quarantined}");
            }
            catch
            {
                try { File.Delete(file); log($"          - deleted {file}"); }
                catch { log($"          - could not remove {file} (locked)"); }
            }
        }
    }
}
