using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace WormKiller
{
    struct NetConnection
    {
        public string Protocol;
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public string State;
        public int Pid;
    }

    // Parses `netstat -ano` into structured connections so we can reason about
    // *established* command-and-control links, not just open local ports.
    static class NetworkInspector
    {
        // Ports commonly used by XWorm / commodity RATs for their C2 channel.
        public static readonly int[] RatPorts =
        {
            1337, 4444, 5555, 6666, 7777, 8888, 9999, 8080,
            1604, 3306, 3389, 5900, 54321, 31337, 50000, 50001, 7000, 2000
        };

        public static List<NetConnection> GetConnections()
        {
            var result = new List<NetConnection>();
            try
            {
                var psi = new ProcessStartInfo("netstat.exe", "-ano")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p == null) return result;
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();

                foreach (string raw in output.Split('\n'))
                {
                    string line = raw.Trim();
                    if (line.Length == 0) continue;
                    if (!line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                        !line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string[] parts = Regex.Split(line, @"\s+");
                    if (parts.Length < 4) continue;

                    var conn = new NetConnection { Protocol = parts[0].ToUpperInvariant() };
                    SplitEndpoint(parts[1], out conn.LocalAddress, out conn.LocalPort);

                    if (conn.Protocol == "TCP" && parts.Length >= 5)
                    {
                        SplitEndpoint(parts[2], out conn.RemoteAddress, out conn.RemotePort);
                        conn.State = parts[3];
                        conn.Pid = ParseInt(parts[4]);
                    }
                    else if (parts.Length >= 4)
                    {
                        // UDP has no state column.
                        SplitEndpoint(parts[2], out conn.RemoteAddress, out conn.RemotePort);
                        conn.State = "";
                        conn.Pid = ParseInt(parts[parts.Length - 1]);
                    }

                    result.Add(conn);
                }
            }
            catch { }
            return result;
        }

        static void SplitEndpoint(string endpoint, out string address, out int port)
        {
            address = endpoint;
            port = 0;
            int idx = endpoint.LastIndexOf(':');
            if (idx < 0) return;
            address = endpoint.Substring(0, idx);
            ParseIntOut(endpoint.Substring(idx + 1), out port);
        }

        static int ParseInt(string s) { ParseIntOut(s, out int v); return v; }
        static void ParseIntOut(string s, out int v) { if (!int.TryParse(s, out v)) v = 0; }

        public static bool IsRoutableRemote(string address)
        {
            if (string.IsNullOrEmpty(address)) return false;
            if (address == "0.0.0.0" || address == "*" || address == "::" ) return false;
            if (address == "127.0.0.1" || address == "::1") return false;
            if (address.StartsWith("10.") || address.StartsWith("192.168.")) return false;
            if (address.StartsWith("169.254.")) return false;
            // 172.16.0.0/12
            if (address.StartsWith("172."))
            {
                string[] o = address.Split('.');
                if (o.Length > 1 && int.TryParse(o[1], out int second) && second >= 16 && second <= 31)
                    return false;
            }
            return true;
        }

        public static bool IsRatPort(int port)
        {
            foreach (int p in RatPorts) if (p == port) return true;
            return false;
        }
    }
}
