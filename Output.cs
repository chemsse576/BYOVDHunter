using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace BYOVDHunter
{
    public static class Output
    {
        private const int BoxWidth = 66;

        public static void PrintBanner()
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"
  ____   ____ _____   _____  _   _             _
 | __ ) / ___|_   _| | ____|| | | |_   _ _ __ | |_ ___ _ __
 |  _ \ \___ \ | |   |  _|  | |_| | | | | '_ \| __/ _ \ '__|
 | |_) | ___) || |   | |___ |  _  | |_| | | | | ||  __/ |
 |____/ |____/ |_|   |_____||_| |_|\__,_|_| |_|\__\___|_|");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  BYOVD Hunter v3.0 - Advanced Vulnerable Driver Detection");
            Console.ForegroundColor = prev;
            Console.WriteLine();
        }

        public static void PrintSystemStatus(SystemProtection s)
        {
            var prev = Console.ForegroundColor;
            string bar = new string('═', 50);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {bar}");
            Console.WriteLine("       S Y S T E M   P R O T E C T I O N");
            Console.WriteLine($"  {bar}");

            PrintStatusLine("Windows        ", s.WindowsVersion + " (Build " + s.BuildNumber + ")", ConsoleColor.White);
            PrintStatusLine("HVCI           ", s.HvciEnabled ? "Enabled" : "DISABLED", s.HvciEnabled ? ConsoleColor.Green : ConsoleColor.Red);
            PrintStatusLine("Secure Boot    ", s.SecureBootEnabled ? "Enabled" : "Disabled", s.SecureBootEnabled ? ConsoleColor.Green : ConsoleColor.Yellow);
            PrintStatusLine("DSE            ", s.DseEnforced ? "Enforced" : "NOT ENFORCED", s.DseEnforced ? ConsoleColor.Green : ConsoleColor.Red);
            PrintStatusLine("Test Signing   ", s.TestSigningEnabled ? "ON" : "OFF", s.TestSigningEnabled ? ConsoleColor.Red : ConsoleColor.Green);
            PrintStatusLine("VBS            ", s.VbsEnabled ? "Enabled" : "Disabled", s.VbsEnabled ? ConsoleColor.Green : ConsoleColor.Yellow);
            PrintStatusLine("WDAC Policy    ", s.WdacPolicyPresent ? "Found" : "Not found", s.WdacPolicyPresent ? ConsoleColor.Green : ConsoleColor.Yellow);
            PrintStatusLine("MS Blocklist   ", s.BlocklistEnabled ? "Enabled" : "DISABLED", s.BlocklistEnabled ? ConsoleColor.Green : ConsoleColor.Red);

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {bar}");

            if (!s.HvciEnabled)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  WARNING: HVCI is OFF. Vulnerable drivers CAN be loaded.");
            }
            if (!s.BlocklistEnabled)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  WARNING: MS Blocklist is OFF. Known-bad drivers NOT blocked.");
            }
            if (s.TestSigningEnabled)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  WARNING: Test signing is ON. Unsigned drivers can be loaded.");
            }

            Console.ForegroundColor = prev;
            Console.WriteLine();
        }

        public static void PrintProgress(string message)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.Write("[*] ");
            Console.ForegroundColor = prev;
            Console.WriteLine(message);
        }

        public static void PrintInfo(string message)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("    " + message);
            Console.ForegroundColor = prev;
        }

        public static void PrintWarning(string message)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[!] ");
            Console.ForegroundColor = prev;
            Console.WriteLine(message);
        }

        public static void PrintResult(DriverResult dr)
        {
            switch (dr.Risk)
            {
                case RiskLevel.Critical: PrintDetailBlock(dr, "CRITICAL", ConsoleColor.Red); break;
                case RiskLevel.High: PrintDetailBlock(dr, "HIGH", ConsoleColor.DarkRed); break;
                case RiskLevel.Medium: PrintMediumBlock(dr); break;
                case RiskLevel.Low: PrintLowLine(dr); break;
                case RiskLevel.Info: PrintInfoResultLine(dr); break;
            }
        }

        private static void PrintDetailBlock(DriverResult dr, string label, ConsoleColor accent)
        {
            string top = "╔" + new string('═', BoxWidth) + "╗";
            string div = "╠" + new string('═', BoxWidth) + "╣";
            string bot = "╚" + new string('═', BoxWidth) + "╝";

            var prev = Console.ForegroundColor;
            Console.ForegroundColor = accent;
            Console.WriteLine();
            Console.WriteLine(top);

            string title = dr.LolMatch != null || dr.BlocklistMatch != null
                ? $"[{label}] Exploitable Driver Found"
                : $"[{label}] Suspicious Driver";
            if (dr.Dispatch != null && dr.DangerousImports.Any(i => i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect))
                title = $"[{label}] Exploitable Driver (IOCTL path confirmed)";

            PrintBoxLine(title, accent);
            Console.ForegroundColor = accent;
            Console.WriteLine(div);

            PrintBoxLine($"Driver          : {dr.FileName}", ConsoleColor.White);
            PrintBoxLine($"Path            : {Trunc(dr.Path, 50)}", ConsoleColor.Gray);
            if (!string.IsNullOrEmpty(dr.SourceLocation))
                PrintBoxLine($"Source          : {dr.SourceLocation}", ConsoleColor.DarkGray);

            var statusColor = dr.IsLoaded ? ConsoleColor.Red : ConsoleColor.Gray;
            PrintBoxLine($"Status          : {(dr.IsLoaded ? "LOADED (active in kernel)" : "On disk only")}", statusColor);

            PrintBoxLine($"SHA256          : {Trunc(dr.Sha256, 50)}", ConsoleColor.Gray);

            string signStr = dr.IsSigned
                ? $"Yes ({Trunc(dr.SignerName, 36)}){(dr.IsSignatureValid ? "" : " [INVALID]")}"
                : "NO - Unsigned";
            PrintBoxLine($"Signed          : {signStr}", dr.IsSigned ? ConsoleColor.Green : ConsoleColor.Red);

            if (dr.CertFlag != null)
                PrintBoxLine($"Cert warning    : {dr.CertFlag.Reason}", ConsoleColor.Red);

            if (dr.Metadata != null && !string.IsNullOrEmpty(dr.Metadata.CompileDate))
            {
                string age = dr.Metadata.AgeYears > 0 ? $" ({dr.Metadata.AgeYears}y old)" : "";
                PrintBoxLine($"Compiled        : {dr.Metadata.CompileDate}{age}", ConsoleColor.Gray);
            }

            if (dr.Metadata != null && !string.IsNullOrEmpty(dr.Metadata.PdbPath))
                PrintBoxLine($"PDB path        : {Trunc(dr.Metadata.PdbPath, 48)}", ConsoleColor.DarkGray);

            PrintBoxLine($"Driver model    : {dr.Framework}{(dr.Framework == DriverFramework.WDM ? " (no framework protections)" : "")}", ConsoleColor.Gray);

            if (dr.Mitigations != null && dr.Mitigations.MissingCount > 0)
            {
                var missing = new List<string>();
                if (!dr.Mitigations.HasASLR) missing.Add("No ASLR");
                if (!dr.Mitigations.HasCFG) missing.Add("No CFG");
                if (!dr.Mitigations.HasDEP) missing.Add("No DEP");
                PrintBoxLine($"Mitigations     : {string.Join(", ", missing)}", ConsoleColor.Yellow);
            }

            if (dr.VersionInfo != null && !string.IsNullOrEmpty(dr.VersionInfo.FileVersion))
                PrintBoxLine($"File version    : {Trunc(dr.VersionInfo.FileVersion, 30)} ({Trunc(dr.VersionInfo.CompanyName, 20)})", ConsoleColor.DarkGray);

            if (dr.VendorMatch != null)
                PrintBoxLine($"Vendor          : KNOWN VULNERABLE - {dr.VendorMatch.Reason}", ConsoleColor.Red);

            foreach (var dev in dr.Devices.Take(3))
            {
                PrintBoxLine($"Device name     : {Trunc(dev.DeviceName, 48)}", ConsoleColor.Cyan);
                if (!string.IsNullOrEmpty(dev.SymbolicLink) && dev.SymbolicLink != dev.DeviceName)
                    PrintBoxLine($"Symbolic link   : {Trunc(dev.SymbolicLink, 48)}", ConsoleColor.Cyan);
                if (!string.IsNullOrEmpty(dev.SddlAccess))
                    PrintBoxLine($"Device access   : {dev.SddlAccess}", dev.SddlAccess.Contains("Everyone") ? ConsoleColor.Red : ConsoleColor.Gray);
            }

            if (dr.LolMatch != null)
            {
                PrintBoxLine("LOLDrivers      : YES - Known vulnerable", ConsoleColor.Red);
                if (dr.LolMatch.CVEs.Count > 0)
                    PrintBoxLine($"CVEs            : {string.Join(", ", dr.LolMatch.CVEs)}", ConsoleColor.Yellow);
                if (dr.LolMatch.Tags.Count > 0)
                    PrintBoxLine($"Tags            : {string.Join(", ", dr.LolMatch.Tags.Take(5))}", ConsoleColor.DarkYellow);
            }
            if (dr.BlocklistMatch != null)
                PrintBoxLine("MS Blocklist    : YES - Microsoft blocked driver", ConsoleColor.Red);
            if (dr.FamilyMatch != null)
                PrintBoxLine($"Known IOCTL     : Pattern matches {dr.FamilyMatch.FamilyName}", ConsoleColor.Red);

            if (dr.IoctlCodes.Count > 0)
            {
                var critical = dr.IoctlCodes.Where(c => c.Method == 3).ToList();
                var anyAccess = dr.IoctlCodes.Where(c => c.Access == 0).ToList();

                PrintBoxLine("IOCTL analysis:", ConsoleColor.Yellow);
                if (critical.Count > 0)
                    PrintBoxLine($"  Method        : METHOD_NEITHER ({critical.Count}x) - raw user pointers!", ConsoleColor.Red);
                if (anyAccess.Count > 0)
                    PrintBoxLine($"  Access        : FILE_ANY_ACCESS ({anyAccess.Count}x) - no privilege required", ConsoleColor.Red);

                var codeStrs = dr.IoctlCodes.Take(6).Select(c => c.CodeHex);
                PrintBoxLine($"  Codes found   : {string.Join(", ", codeStrs)}", ConsoleColor.Yellow);
            }

            if (dr.Dispatch != null)
            {
                PrintBoxLine("Dispatch analysis:", ConsoleColor.Yellow);
                if (dr.Dispatch.CreateAccessCheck != AccessCheckVerdict.Unknown)
                    PrintBoxLine($"  IRP_MJ_CREATE          : {dr.Dispatch.CreateAccessCheck}", dr.Dispatch.CreateAccessCheck == AccessCheckVerdict.NoChecks ? ConsoleColor.Red : ConsoleColor.Green);
                if (dr.Dispatch.DeviceControlHandlerRva != 0)
                    PrintBoxLine($"  IRP_MJ_DEVICE_CONTROL  : handler at RVA 0x{dr.Dispatch.DeviceControlHandlerRva:X}", ConsoleColor.DarkGray);
                if (dr.Dispatch.BufferValidation != BufferValidation.Unknown)
                    PrintBoxLine($"  Buffer validation      : {dr.Dispatch.BufferValidation}", dr.Dispatch.BufferValidation == BufferValidation.NoValidation ? ConsoleColor.Red : ConsoleColor.Green);
                if (dr.Dispatch.HasPreviousModeCheck)
                    PrintBoxLine("  PreviousMode check     : FOUND", ConsoleColor.Green);
                else if (dr.Dispatch.DeviceControlHandlerRva != 0)
                    PrintBoxLine("  PreviousMode check     : NOT FOUND", ConsoleColor.Yellow);
                if (dr.Dispatch.AllSameHandler)
                    PrintBoxLine("  All same handler       : YES (lazy pattern)", ConsoleColor.Yellow);
            }

            if (dr.DangerousImports.Count > 0)
            {
                bool hasReach = dr.DangerousImports.Any(i => i.Reachability != Reachability.Unknown);
                if (hasReach)
                {
                    PrintBoxLine("IOCTL -> Import reachability:", ConsoleColor.Yellow);
                    foreach (var imp in dr.DangerousImports.Where(i => i.Reachability != Reachability.Unknown))
                    {
                        string reachStr = imp.Reachability.ToString().ToUpper();
                        var color = imp.Reachability == Reachability.Direct ? ConsoleColor.Red
                            : imp.Reachability == Reachability.Indirect ? ConsoleColor.DarkRed
                            : ConsoleColor.DarkGray;
                        string taintStr = imp.Taint != TaintStatus.Unknown ? $" [{imp.Taint}]" : "";
                        PrintBoxLine($"  {imp.FunctionName,-25}: {reachStr}{taintStr}", color);
                    }
                }
                else
                {
                    PrintBoxLine("Dangerous imports:", ConsoleColor.Yellow);
                    foreach (var imp in dr.DangerousImports.Take(8))
                        PrintBoxLine($"  - {imp.FunctionName} ({imp.Description})", ConsoleColor.Yellow);
                }
            }

            if (dr.ExportedDangerousFunctions.Count > 0)
            {
                PrintBoxLine("Dangerous EXPORTS (proxy driver):", ConsoleColor.Magenta);
                foreach (string exp in dr.ExportedDangerousFunctions.Take(5))
                    PrintBoxLine($"  - {exp}", ConsoleColor.Magenta);
            }

            if (dr.SuspiciousStrings.Count > 0)
            {
                PrintBoxLine("Suspicious strings:", ConsoleColor.Magenta);
                foreach (string s in dr.SuspiciousStrings.Take(5))
                    PrintBoxLine($"  - \"{s}\"", ConsoleColor.Magenta);
            }

            if (dr.Sections.Any(s => s.IsRWX))
            {
                var rwx = dr.Sections.Where(s => s.IsRWX).Select(s => s.Name);
                PrintBoxLine($"RWX sections    : {string.Join(", ", rwx)} (code injection surface)", ConsoleColor.Red);
            }
            if (dr.Sections.Any(s => s.IsHighEntropy))
            {
                var he = dr.Sections.Where(s => s.IsHighEntropy).Select(s => $"{s.Name} ({s.Entropy:F1})");
                PrintBoxLine($"High entropy    : {string.Join(", ", he)} (possibly packed)", ConsoleColor.Yellow);
            }

            if (dr.Behaviors != BehaviorTag.None)
            {
                var behaviorNames = new List<string>();
                if (dr.Behaviors.HasFlag(BehaviorTag.B1_ProtectedServiceTermination)) behaviorNames.Add("B1:SvcTermination");
                if (dr.Behaviors.HasFlag(BehaviorTag.B2_PrivilegedHandleLeak))       behaviorNames.Add("B2:HandleLeak");
                if (dr.Behaviors.HasFlag(BehaviorTag.B3_UnsafePoolAllocation))       behaviorNames.Add("B3:PoolAlloc");
                if (dr.Behaviors.HasFlag(BehaviorTag.B4_DynamicKernelCodeExec))      behaviorNames.Add("B4:KernelExec");
                if (dr.Behaviors.HasFlag(BehaviorTag.B5_MismatchedMemoryMapping))    behaviorNames.Add("B5:MemMap");
                if (dr.Behaviors.HasFlag(BehaviorTag.B6_CodeIntegrityTampering))     behaviorNames.Add("B6:CITamper");
                if (dr.Behaviors.HasFlag(BehaviorTag.B7_RemoteHandleClosure))        behaviorNames.Add("B7:HandleClose");
                if (dr.Behaviors.HasFlag(BehaviorTag.B8_ArbitraryMemoryWrite))       behaviorNames.Add("B8:MemWrite");
                if (dr.Behaviors.HasFlag(BehaviorTag.B9_ArbitraryMsrWrite))          behaviorNames.Add("B9:MsrWrite");
                if (dr.Behaviors.HasFlag(BehaviorTag.B10_ArbitraryPortIO))           behaviorNames.Add("B10:PortIO");
                if (dr.Behaviors.HasFlag(BehaviorTag.B11_PhysicalMemoryMapping))     behaviorNames.Add("B11:PhysMemMap");
                if (dr.Behaviors.HasFlag(BehaviorTag.B12_TaintedKernelArgs))         behaviorNames.Add("B12:TaintedArgs");
                if (dr.Behaviors.HasFlag(BehaviorTag.B13_ExecWritableRemap))         behaviorNames.Add("B13:ExecRemap");
                if (dr.Behaviors.HasFlag(BehaviorTag.B14_UnsafeRtlQueryRegistry))    behaviorNames.Add("B14:UnsafeRegQuery");
                if (dr.Behaviors.HasFlag(BehaviorTag.B15_RtlQueryRegistryTampering)) behaviorNames.Add("B15:RegTamper");
                PrintBoxLine($"Behaviors       : {string.Join(", ", behaviorNames)}", ConsoleColor.Magenta);
            }

            if (!string.IsNullOrEmpty(dr.RiskReason))
                PrintBoxLine($"Risk            : {dr.RiskReason}", accent);
            if (!string.IsNullOrEmpty(dr.Impact))
                PrintBoxLine($"Impact          : {dr.Impact}", accent);
            if (!string.IsNullOrEmpty(dr.ExploitUse))
                PrintBoxLine($"Exploit use     : {dr.ExploitUse}", accent);
            if (!string.IsNullOrEmpty(dr.Note))
                PrintBoxLine($"Note            : {dr.Note}", ConsoleColor.White);

            Console.ForegroundColor = accent;
            Console.WriteLine(bot);
            Console.ForegroundColor = prev;
        }

        private static void PrintMediumBlock(DriverResult dr)
        {
            string top = "┌" + new string('─', BoxWidth) + "┐";
            string bot = "└" + new string('─', BoxWidth) + "┘";

            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine();
            Console.WriteLine(top);

            string title = $"[MEDIUM] {dr.FileName}";
            if (dr.DangerousImports.All(i => i.Reachability == Reachability.NotReachable) && dr.DangerousImports.Count > 0)
                title += " (false positive reduced)";
            PrintBoxLineThin(title, ConsoleColor.Yellow);

            if (!string.IsNullOrEmpty(dr.RiskReason))
                PrintBoxLineThin(dr.RiskReason, ConsoleColor.DarkGray);

            var details = new List<string>();
            details.Add($"Driver: {dr.Framework}");
            details.Add($"Signed: {(dr.IsSigned ? "Yes (" + Trunc(dr.SignerName, 20) + ")" : "No")}");
            details.Add($"Loaded: {(dr.IsLoaded ? "Yes" : "No")}");
            if (dr.Metadata != null && dr.Metadata.AgeYears > 0)
                details.Add($"Age: {dr.Metadata.AgeYears}y");
            PrintBoxLineThin(string.Join(" | ", details), ConsoleColor.DarkGray);

            if (dr.DangerousImports.Count > 0)
            {
                var impNames = dr.DangerousImports.Take(4).Select(i =>
                {
                    string r = i.Reachability != Reachability.Unknown ? $"[{i.Reachability}]" : "";
                    return i.FunctionName + r;
                });
                PrintBoxLineThin("Imports: " + string.Join(", ", impNames), ConsoleColor.DarkYellow);
            }

            if (dr.Behaviors != BehaviorTag.None)
            {
                var bNames = FormatBehaviorTags(dr.Behaviors);
                if (bNames.Length > 0)
                    PrintBoxLineThin("Behaviors: " + bNames, ConsoleColor.Magenta);
            }

            if (!string.IsNullOrEmpty(dr.Note))
                PrintBoxLineThin(dr.Note, ConsoleColor.DarkGray);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(bot);
            Console.ForegroundColor = prev;
        }

        private static string FormatBehaviorTags(BehaviorTag b)
        {
            var names = new List<string>();
            if (b.HasFlag(BehaviorTag.B1_ProtectedServiceTermination)) names.Add("B1:SvcTermination");
            if (b.HasFlag(BehaviorTag.B2_PrivilegedHandleLeak))       names.Add("B2:HandleLeak");
            if (b.HasFlag(BehaviorTag.B3_UnsafePoolAllocation))       names.Add("B3:PoolAlloc");
            if (b.HasFlag(BehaviorTag.B4_DynamicKernelCodeExec))      names.Add("B4:KernelExec");
            if (b.HasFlag(BehaviorTag.B5_MismatchedMemoryMapping))    names.Add("B5:MemMap");
            if (b.HasFlag(BehaviorTag.B6_CodeIntegrityTampering))     names.Add("B6:CITamper");
            if (b.HasFlag(BehaviorTag.B7_RemoteHandleClosure))        names.Add("B7:HandleClose");
            if (b.HasFlag(BehaviorTag.B8_ArbitraryMemoryWrite))       names.Add("B8:MemWrite");
            if (b.HasFlag(BehaviorTag.B9_ArbitraryMsrWrite))          names.Add("B9:MsrWrite");
            if (b.HasFlag(BehaviorTag.B10_ArbitraryPortIO))           names.Add("B10:PortIO");
            if (b.HasFlag(BehaviorTag.B11_PhysicalMemoryMapping))     names.Add("B11:PhysMemMap");
            if (b.HasFlag(BehaviorTag.B12_TaintedKernelArgs))         names.Add("B12:TaintedArgs");
            if (b.HasFlag(BehaviorTag.B13_ExecWritableRemap))         names.Add("B13:ExecRemap");
            if (b.HasFlag(BehaviorTag.B14_UnsafeRtlQueryRegistry))    names.Add("B14:UnsafeRegQuery");
            if (b.HasFlag(BehaviorTag.B15_RtlQueryRegistryTampering)) names.Add("B15:RegTamper");
            return string.Join(", ", names);
        }

        private static void PrintLowLine(DriverResult dr)
        {
            if (string.IsNullOrEmpty(dr.RiskReason)) return;
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    [LOW]  ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(dr.FileName);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($" - {dr.RiskReason}");
            if (dr.Metadata != null && !string.IsNullOrEmpty(dr.Metadata.CompileDate))
                Console.Write($", compiled {dr.Metadata.CompileDate}");
            Console.WriteLine();
            Console.ForegroundColor = prev;
        }

        private static void PrintInfoResultLine(DriverResult dr)
        {
            if (string.IsNullOrEmpty(dr.RiskReason)) return;
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("    [INFO] ");
            Console.Write($"{dr.FileName} - {dr.RiskReason}");
            if (dr.IsWhitelisted) Console.Write(" - Skipped");
            Console.WriteLine();
            Console.ForegroundColor = prev;
        }

        public static void PrintExploitableRecap(List<DriverResult> loaded)
        {
            if (loaded.Count == 0) return;
            var prev = Console.ForegroundColor;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            string bar = new string('═', 66);
            Console.WriteLine($"  {bar}");
            Console.WriteLine("   LOADED EXPLOITABLE DRIVERS - IMMEDIATE RISK");
            Console.WriteLine($"  {bar}");
            Console.ForegroundColor = prev;
            Console.WriteLine();

            foreach (var dr in loaded)
            {
                Console.ForegroundColor = dr.Risk == RiskLevel.Critical ? ConsoleColor.Red : ConsoleColor.DarkRed;
                Console.Write($"  ● {dr.FileName}");

                if (dr.LolMatch != null) { Console.ForegroundColor = ConsoleColor.Red; Console.Write("  [LOLDrivers]"); }
                if (dr.BlocklistMatch != null) { Console.ForegroundColor = ConsoleColor.Red; Console.Write("  [MS-Blocklist]"); }
                if (!dr.IsSigned) { Console.ForegroundColor = ConsoleColor.Red; Console.Write("  [UNSIGNED]"); }
                Console.WriteLine();

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("    Signer  : ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(dr.IsSigned ? dr.SignerName : "NONE");

                if (dr.LolMatch != null && dr.LolMatch.CVEs.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    CVEs    : ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(string.Join(", ", dr.LolMatch.CVEs));
                }

                if (dr.Devices.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    Device  : ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine(dr.Devices[0].DeviceName);
                }

                var reachableImps = dr.DangerousImports
                    .Where(i => i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect)
                    .ToList();
                if (reachableImps.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    Reach   : ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(string.Join(", ", reachableImps.Take(4).Select(i => $"{i.FunctionName}({i.Reachability})")));
                }

                var caps = new List<string>();
                bool hasMem = dr.DangerousImports.Any(i => i.Category == "PhysMem");
                bool hasProc = dr.DangerousImports.Any(i => i.Category == "ProcKill" || i.Category == "ProcManip");
                bool hasCb = dr.DangerousImports.Any(i => i.Category == "CallbackUnreg" || i.Category == "CallbackReg");
                if (hasMem) caps.Add("Kernel R/W");
                if (hasProc) caps.Add("Process kill");
                if (hasCb) caps.Add("Callback removal");
                if (caps.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    Exploit : ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(string.Join(" + ", caps));
                }

                var abuses = new List<string>();
                if (hasMem) { abuses.Add("Privilege Escalation"); abuses.Add("EDR bypass"); abuses.Add("Credential theft"); }
                if (hasProc) abuses.Add("EDR kill");
                if (hasCb) abuses.Add("EDR blinding");
                if (hasMem || dr.LolMatch != null) abuses.Add("Persistence");
                if (abuses.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    Abuse   : ");
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.WriteLine(string.Join(", ", abuses));
                }
                Console.WriteLine();
            }
            Console.ForegroundColor = prev;
        }

        public static void PrintSummary(ScanSummary s)
        {
            var prev = Console.ForegroundColor;
            Console.WriteLine();
            string bar = new string('═', 60);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {bar}");
            Console.WriteLine("              S C A N   S U M M A R Y");
            Console.WriteLine($"  {bar}");

            PrintSumLine("Scan paths                 ", string.Join(", ", s.ScanPaths), ConsoleColor.DarkGray);
            PrintSumLine("Total drivers scanned      ", s.TotalScanned.ToString(), ConsoleColor.White);
            PrintSumLine("Whitelisted (skipped)      ", s.WhitelistedCount.ToString(), ConsoleColor.DarkGray);
            PrintSumLine("Currently loaded           ", s.CurrentlyLoaded.ToString(), ConsoleColor.White);

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Databases:");
            PrintSumLine("  LOLDrivers matches       ", s.LolDriversMatches.ToString(), s.LolDriversMatches > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  MS Blocklist matches     ", s.MsBlocklistMatches.ToString(), s.MsBlocklistMatches > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  Known IOCTL family match ", s.IoctlFamilyMatches.ToString(), s.IoctlFamilyMatches > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
            PrintSumLine("  Compromised cert matches ", s.CompromisedCertMatches.ToString(), s.CompromisedCertMatches > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  Known vuln vendor        ", s.KnownVulnVendorMatches.ToString(), ConsoleColor.DarkGray);

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Static analysis:");
            PrintSumLine("  IOCTL-reachable (confirm)", s.IoctlReachableConfirmed.ToString(), s.IoctlReachableConfirmed > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  Tainted parameters       ", s.TaintedParams.ToString(), s.TaintedParams > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  Unreachable (FP reduced) ", s.UnreachableFpReduced.ToString(), ConsoleColor.DarkGray);
            PrintSumLine("  Could not determine      ", s.CouldNotDetermine.ToString(), ConsoleColor.DarkGray);

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  By severity:");
            PrintSumLine("  CRITICAL (exploitable)   ", s.CriticalCount.ToString(), s.CriticalCount > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            PrintSumLine("  HIGH                     ", s.HighCount.ToString(), s.HighCount > 0 ? ConsoleColor.DarkRed : ConsoleColor.Green);
            PrintSumLine("  MEDIUM                   ", s.MediumCount.ToString(), s.MediumCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
            PrintSumLine("  LOW                      ", s.LowCount.ToString(), ConsoleColor.DarkGray);

            if (s.BehaviorCounts != null && s.BehaviorCounts.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("  Behavior analysis:");
                foreach (var kv in s.BehaviorCounts)
                {
                    if (kv.Value > 0)
                    {
                        var color = kv.Key.StartsWith("B14") || kv.Key.StartsWith("B6") || kv.Key.StartsWith("B4")
                            ? ConsoleColor.Red
                            : kv.Key.StartsWith("B1") || kv.Key.StartsWith("B8") || kv.Key.StartsWith("B7")
                                ? ConsoleColor.DarkRed
                                : ConsoleColor.Yellow;
                        PrintSumLine($"  {kv.Key,-25}", kv.Value.ToString(), color);
                    }
                }
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  PE security:");
            PrintSumLine("  Missing ASLR             ", s.MissingAslr.ToString(), ConsoleColor.DarkGray);
            PrintSumLine("  Missing CFG              ", s.MissingCfg.ToString(), ConsoleColor.DarkGray);
            PrintSumLine("  RWX sections             ", s.RwxSections.ToString(), s.RwxSections > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray);
            PrintSumLine("  High entropy sections    ", s.HighEntropySections.ToString(), s.HighEntropySections > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray);

            if (s.SystemStatus != null)
            {
                string posture = "";
                if (!s.SystemStatus.HvciEnabled) posture += "HVCI: OFF";
                if (!s.SystemStatus.BlocklistEnabled)
                    posture += (posture.Length > 0 ? " | " : "") + "Blocklist: OFF";
                if (posture.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  System posture: {posture}");
                }
            }

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {bar}");
            Console.ForegroundColor = prev;
        }

        public static void ExportJson(List<DriverResult> results, ScanSummary summary, string outPath)
        {
            var export = new Dictionary<string, object>
            {
                { "scanDate", DateTime.UtcNow.ToString("o") },
                { "summary", SummaryToDict(summary) },
                { "findings", results
                    .Where(r => r.Risk >= RiskLevel.Low || r.LolMatch != null || r.BlocklistMatch != null)
                    .Select(DriverToDict).ToList() }
            };
            var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            string json = serializer.Serialize(export);
            File.WriteAllText(outPath, FormatJson(json), Encoding.UTF8);
        }

        public static void ExportCsv(List<DriverResult> results, string outPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("FileName,Path,SHA256,Signed,SignerName,Loaded,Whitelisted,Framework," +
                "LOLDrivers,MsBlocklist,IoctlFamily,VulnVendor,DeviceNames,IoctlCodes," +
                "RiskLevel,RiskReason,Impact,ExploitUse,DangerousImports,Reachability,SuspiciousStrings," +
                "CompileDate,MissingMitigations,Behaviors,Note");

            foreach (var r in results.Where(r => r.Risk >= RiskLevel.Low || r.LolMatch != null))
            {
                sb.AppendLine(string.Join(",",
                    Esc(r.FileName), Esc(r.Path), Esc(r.Sha256),
                    r.IsSigned ? "Yes" : "No", Esc(r.SignerName),
                    r.IsLoaded ? "Yes" : "No", r.IsWhitelisted ? "Yes" : "No",
                    r.Framework.ToString(),
                    r.LolMatch != null ? "Yes" : "No",
                    r.BlocklistMatch != null ? "Yes" : "No",
                    Esc(r.FamilyMatch?.FamilyName ?? ""),
                    Esc(r.VendorMatch?.VendorName ?? ""),
                    Esc(string.Join("; ", r.Devices.Select(d => d.DeviceName))),
                    Esc(string.Join("; ", r.IoctlCodes.Select(c => c.CodeHex))),
                    r.Risk.ToString(), Esc(r.RiskReason), Esc(r.Impact), Esc(r.ExploitUse),
                    Esc(string.Join("; ", r.DangerousImports.Select(i => $"{i.FunctionName}({i.Reachability})"))),
                    Esc(string.Join("; ", r.DangerousImports.Where(i => i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect).Select(i => i.FunctionName))),
                    Esc(string.Join("; ", r.SuspiciousStrings)),
                    Esc(r.Metadata?.CompileDate ?? ""),
                    Esc(r.Mitigations != null ? string.Join("; ",
                        new[] { !r.Mitigations.HasASLR ? "NoASLR" : null, !r.Mitigations.HasCFG ? "NoCFG" : null }
                            .Where(s => s != null)) : ""),
                    Esc(r.Behaviors != BehaviorTag.None ? FormatBehaviorTags(r.Behaviors).Replace(", ", "|") : ""),
                    Esc(r.Note)
                ));
            }
            File.WriteAllText(outPath, sb.ToString(), Encoding.UTF8);
        }

        #region Helpers

        private static void PrintBoxLine(string text, ConsoleColor color)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("║ ");
            Console.ForegroundColor = color;
            string content = text.Length > BoxWidth - 2 ? text.Substring(0, BoxWidth - 5) + "..." : text;
            Console.Write(content);
            int pad = BoxWidth - 1 - content.Length;
            if (pad > 0) Console.Write(new string(' ', pad));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("║");
            Console.ForegroundColor = prev;
        }

        private static void PrintBoxLineThin(string text, ConsoleColor color)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("│ ");
            Console.ForegroundColor = color;
            string content = text.Length > BoxWidth - 2 ? text.Substring(0, BoxWidth - 5) + "..." : text;
            Console.Write(content);
            int pad = BoxWidth - 1 - content.Length;
            if (pad > 0) Console.Write(new string(' ', pad));
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("│");
            Console.ForegroundColor = prev;
        }

        private static void PrintStatusLine(string label, string value, ConsoleColor color)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {label}: ");
            Console.ForegroundColor = color;
            Console.WriteLine(value);
            Console.ForegroundColor = prev;
        }

        private static void PrintSumLine(string label, string value, ConsoleColor color)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"  {label}: ");
            Console.ForegroundColor = color;
            Console.WriteLine(value);
            Console.ForegroundColor = prev;
        }

        private static string Trunc(string s, int maxLen)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length > maxLen ? s.Substring(0, maxLen - 3) + "..." : s;
        }

        private static string Esc(string val)
        {
            if (string.IsNullOrEmpty(val)) return "\"\"";
            if (val.Contains(",") || val.Contains("\"") || val.Contains("\n"))
                return "\"" + val.Replace("\"", "\"\"") + "\"";
            return val;
        }

        private static Dictionary<string, object> SummaryToDict(ScanSummary s)
        {
            return new Dictionary<string, object>
            {
                {"totalScanned", s.TotalScanned}, {"whitelisted", s.WhitelistedCount},
                {"loaded", s.CurrentlyLoaded}, {"lolDrivers", s.LolDriversMatches},
                {"msBlocklist", s.MsBlocklistMatches}, {"ioctlFamily", s.IoctlFamilyMatches},
                {"compromisedCerts", s.CompromisedCertMatches}, {"vulnVendors", s.KnownVulnVendorMatches},
                {"ioctlReachable", s.IoctlReachableConfirmed}, {"tainted", s.TaintedParams},
                {"fpReduced", s.UnreachableFpReduced},
                {"critical", s.CriticalCount}, {"high", s.HighCount},
                {"medium", s.MediumCount}, {"low", s.LowCount},
                {"behaviorB14", s.BehaviorB14Count},
                {"behaviorCounts", s.BehaviorCounts},
            };
        }

        private static Dictionary<string, object> DriverToDict(DriverResult r)
        {
            var d = new Dictionary<string, object>
            {
                {"fileName", r.FileName}, {"path", r.Path}, {"sha256", r.Sha256},
                {"signed", r.IsSigned}, {"signerName", r.SignerName},
                {"loaded", r.IsLoaded}, {"whitelisted", r.IsWhitelisted},
                {"framework", r.Framework.ToString()},
                {"riskLevel", r.Risk.ToString()}, {"riskReason", r.RiskReason},
                {"impact", r.Impact}, {"exploitUse", r.ExploitUse}, {"note", r.Note},
                {"dangerousImports", r.DangerousImports.Select(i => new Dictionary<string, object>
                    { {"name", i.FunctionName}, {"category", i.Category}, {"reachability", i.Reachability.ToString()}, {"taint", i.Taint.ToString()} }).ToList()},
                {"devices", r.Devices.Select(d2 => d2.DeviceName).ToList()},
                {"ioctlCodes", r.IoctlCodes.Select(c => new Dictionary<string, object>
                    { {"code", c.CodeHex}, {"method", c.MethodName}, {"access", c.AccessName} }).ToList()},
                {"suspiciousStrings", r.SuspiciousStrings},
                {"behaviors", r.Behaviors != BehaviorTag.None ? FormatBehaviorTags(r.Behaviors) : ""},
                {"lolDrivers", r.LolMatch != null},
                {"msBlocklist", r.BlocklistMatch != null},
            };
            if (r.LolMatch != null)
            {
                d["cves"] = r.LolMatch.CVEs;
                d["tags"] = r.LolMatch.Tags;
            }
            if (r.Metadata != null)
            {
                d["compileDate"] = r.Metadata.CompileDate;
                d["pdbPath"] = r.Metadata.PdbPath;
            }
            if (r.FamilyMatch != null)
                d["ioctlFamily"] = r.FamilyMatch.FamilyName;
            if (r.VendorMatch != null)
                d["vulnVendor"] = r.VendorMatch.VendorName;
            return d;
        }

        private static string FormatJson(string json)
        {
            var sb = new StringBuilder();
            int indent = 0;
            bool inString = false;
            bool escaped = false;
            foreach (char c in json)
            {
                if (escaped) { sb.Append(c); escaped = false; continue; }
                if (c == '\\' && inString) { sb.Append(c); escaped = true; continue; }
                if (c == '"') { inString = !inString; sb.Append(c); continue; }
                if (inString) { sb.Append(c); continue; }
                switch (c)
                {
                    case '{': case '[':
                        sb.Append(c); sb.AppendLine(); indent++; sb.Append(new string(' ', indent * 2)); break;
                    case '}': case ']':
                        sb.AppendLine(); indent--; sb.Append(new string(' ', indent * 2)); sb.Append(c); break;
                    case ',':
                        sb.Append(c); sb.AppendLine(); sb.Append(new string(' ', indent * 2)); break;
                    case ':': sb.Append(c); sb.Append(' '); break;
                    default: if (!char.IsWhiteSpace(c)) sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        #endregion
    }
}
