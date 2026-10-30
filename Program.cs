using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace BYOVDHunter
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            bool forceUpdate = HasFlag(args, "--update");
            bool jsonOut = HasFlag(args, "--json");
            bool csvOut = HasFlag(args, "--csv");
            bool noWhitelist = HasFlag(args, "--no-whitelist");
            bool scanDriverStore = HasFlag(args, "--scan-driverstore");
            bool verbose = HasFlag(args, "--verbose");
            bool criticalOnly = HasFlag(args, "--critical-only");
            bool highAndAbove = HasFlag(args, "--high-and-above");
            bool loadedOnly = HasFlag(args, "--loaded-only");
            bool noTaint = HasFlag(args, "--no-taint");
            bool noColor = HasFlag(args, "--no-color");
            bool showHelp = HasFlag(args, "-h") || HasFlag(args, "--help");
            string customDbPath = GetArgValue(args, "--db");
            string extraScanPath = GetArgValue(args, "--scan-path");
            string exportPath = GetArgValue(args, "--export");

            if (showHelp)
            {
                Console.WriteLine("BYOVDHunter v3.0 - Advanced Vulnerable Driver Detection");
                Console.WriteLine();
                Console.WriteLine("Usage: BYOVDHunter.exe [options]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("  --update             Update LOLDrivers database");
                Console.WriteLine("  --json               Export results to BYOVDHunter_report.json");
                Console.WriteLine("  --csv                Export results to BYOVDHunter_report.csv");
                Console.WriteLine("  --export <file>      Export full report (auto-detect format)");
                Console.WriteLine("  --db <path>          Use local LOLDrivers JSON (offline mode)");
                Console.WriteLine("  --no-whitelist       Disable OS driver whitelist");
                Console.WriteLine("  --scan-path <dir>    Scan additional directory for .sys files");
                Console.WriteLine("  --scan-driverstore   Also scan DriverStore\\FileRepository");
                Console.WriteLine("  --verbose            Show all drivers including INFO/clean");
                Console.WriteLine("  --critical-only      Show only CRITICAL findings");
                Console.WriteLine("  --high-and-above     Show only HIGH and CRITICAL");
                Console.WriteLine("  --loaded-only        Only analyze loaded drivers");
                Console.WriteLine("  --no-taint           Skip taint analysis (faster)");
                Console.WriteLine("  --no-color           Disable colored output");
                Console.WriteLine("  -h, --help           Show this help");
                return 0;
            }

            Output.PrintBanner();

            if (noWhitelist)
            {
                Scanner.SetWhitelistEnabled(false);
                Output.PrintWarning("Whitelist disabled - all drivers will be analyzed.");
            }

            bool isAdmin = false;
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { }

            if (!isAdmin)
            {
                Output.PrintWarning("Not running as Administrator. Some drivers may be inaccessible.");
                Console.WriteLine();
            }

            // System protection status
            Output.PrintProgress("Checking system protection status...");
            var sysStatus = SystemStatus.Check();
            Output.PrintSystemStatus(sysStatus);

            // LOLDrivers database
            var db = new LolDriversDb();
            string cachePath = customDbPath ?? LolDriversDb.GetCachePath();

            Output.PrintProgress("Loading LOLDrivers database...");
            if (customDbPath != null)
            {
                if (!File.Exists(customDbPath))
                {
                    Output.PrintWarning($"DB file not found: {customDbPath}");
                    Output.PrintWarning("Continuing in heuristic-only mode.");
                }
            }
            else if (forceUpdate || !File.Exists(cachePath))
            {
                Output.PrintInfo("Downloading from loldrivers.io...");
                if (!db.Download(cachePath) && !File.Exists(cachePath))
                {
                    Output.PrintWarning("Download failed. Use --db for offline mode.");
                    Output.PrintInfo("  https://www.loldrivers.io/api/drivers.json");
                }
            }

            if (File.Exists(cachePath))
            {
                if (db.Load(cachePath))
                    Output.PrintInfo($"Loaded {db.Count} known-bad driver hashes.");
                else
                    Output.PrintWarning("Failed to parse LOLDrivers DB.");
            }

            // Discover drivers
            var scanPaths = new List<string> { "System32\\drivers", "Registry" };
            if (scanDriverStore) scanPaths.Add("DriverStore");
            if (!string.IsNullOrEmpty(extraScanPath)) scanPaths.Add(extraScanPath);

            Output.PrintProgress("Discovering driver files...");
            var driverPaths = Scanner.DiscoverDriverPaths(extraScanPath, scanDriverStore);
            Output.PrintInfo($"Found {driverPaths.Count} driver files.");

            Output.PrintProgress("Enumerating loaded kernel drivers...");
            var loadedDrivers = Scanner.GetLoadedDriverBaseNames();
            Output.PrintInfo($"Detected {loadedDrivers.Count} loaded drivers.");

            Output.PrintProgress("Scanning drivers (deep analysis: imports, dispatch, reachability, taint)...");
            Console.WriteLine();

            var results = new List<DriverResult>();
            int scanned = 0, deepAnalyzed = 0;
            var sw = Stopwatch.StartNew();

            foreach (string driverPath in driverPaths.OrderBy(p => p))
            {
                scanned++;
                if (scanned % 50 == 0)
                    Output.PrintInfo($"  Scanned {scanned}/{driverPaths.Count}...");

                var dr = new DriverResult
                {
                    Path = driverPath,
                    FileName = Path.GetFileName(driverPath)
                };

                // Source location
                string lowerPath = driverPath.ToLowerInvariant();
                if (lowerPath.Contains("driverstore")) dr.SourceLocation = "DriverStore";
                else if (lowerPath.Contains(@"system32\drivers")) dr.SourceLocation = "System32\\drivers";
                else dr.SourceLocation = Path.GetDirectoryName(driverPath);

                // Hash
                try { dr.Sha256 = Scanner.ComputeSha256(driverPath); }
                catch (Exception ex)
                {
                    dr.Error = $"Hash failed: {ex.Message}";
                    dr.Sha256 = "";
                    dr.Risk = RiskLevel.Info;
                    results.Add(dr);
                    continue;
                }

                dr.IsLoaded = loadedDrivers.Contains(dr.FileName);
                if (loadedOnly && !dr.IsLoaded) continue;

                // DB lookups
                dr.LolMatch = db.Lookup(dr.Sha256);
                dr.BlocklistMatch = VulnDatabase.CheckMsBlocklist(
                    dr.Sha256, sysStatus.HvciEnabled, sysStatus.BlocklistEnabled);

                // Quick signature check for whitelist decision
                try
                {
                    Scanner.CheckSignature(driverPath, out bool isSig, out bool isVal, out string signer);
                    dr.IsSigned = isSig;
                    dr.IsSignatureValid = isVal;
                    dr.SignerName = signer;
                }
                catch { }

                dr.IsWhitelisted = Scanner.IsWhitelisted(dr.FileName, dr.SignerName, driverPath);

                // Whitelist shortcut
                if (dr.IsWhitelisted && dr.LolMatch == null && dr.BlocklistMatch == null)
                {
                    dr.Risk = RiskLevel.Info;
                    dr.RiskReason = "Whitelisted (Microsoft core driver, signature verified)";
                    results.Add(dr);
                    continue;
                }

                // Possible driver replacement attack
                if (Scanner.IsWhitelistedNameOnly(dr.FileName) && !dr.IsWhitelisted)
                {
                    dr.Note = "WARNING: filename matches whitelist but signature does not (possible driver replacement)";
                }

                // Read file for deep analysis
                byte[] fileData = null;
                try { fileData = PeParser.ReadFile(driverPath); }
                catch { }

                if (fileData != null)
                {
                    // Import analysis
                    dr.DangerousImports = Scanner.FindDangerousImports(fileData);

                    // Import categorization
                    var allImports = PeParser.GetImportedFunctions(fileData);
                    dr.Framework = PeAnalyzer.DetectFramework(allImports);

                    // Export analysis
                    var exports = PeParser.GetExportedFunctions(fileData);
                    dr.ExportedDangerousFunctions = PeAnalyzer.FindDangerousExports(exports);

                    // PE metadata
                    dr.Metadata = PeAnalyzer.ExtractMetadata(fileData);
                    dr.Mitigations = PeAnalyzer.CheckMitigations(fileData);
                    dr.Sections = PeAnalyzer.AnalyzeSections(fileData);

                    // Version info
                    dr.VersionInfo = PeAnalyzer.ExtractVersionInfo(driverPath);

                    // Certificate flags
                    int driverAge = dr.Metadata?.AgeYears ?? 0;
                    dr.CertFlag = PeAnalyzer.CheckCertificateFlags(dr.SignerName, driverAge);

                    // Vendor match
                    dr.VendorMatch = VulnDatabase.MatchVendor(
                        dr.SignerName, dr.VersionInfo?.CompanyName ?? "");

                    // Deep analysis (device names, IOCTL, dispatch, reachability, taint)
                    if (dr.DangerousImports.Count > 0 || dr.LolMatch != null || dr.BlocklistMatch != null)
                    {
                        deepAnalyzed++;
                        Scanner.DeepAnalysis(dr, fileData, noTaint);

                        // IOCTL family match
                        if (dr.IoctlCodes.Count > 0)
                        {
                            dr.FamilyMatch = VulnDatabase.MatchIoctlFamily(
                                dr.IoctlCodes.Select(c => c.Code));
                        }
                    }
                }

                Scanner.AssessRisk(dr, sysStatus);
                results.Add(dr);
            }

            sw.Stop();
            Output.PrintInfo($"  Deep analysis on {deepAnalyzed} drivers. Completed in {sw.Elapsed.TotalSeconds:F1}s.");
            Console.WriteLine();

            // Sort and display results
            var criticals = results.Where(r => r.Risk == RiskLevel.Critical).OrderByDescending(r => r.IsLoaded).ToList();
            var highs = results.Where(r => r.Risk == RiskLevel.High).OrderByDescending(r => r.IsLoaded).ToList();
            var mediums = results.Where(r => r.Risk == RiskLevel.Medium).OrderByDescending(r => r.IsLoaded).ToList();
            var lows = results.Where(r => r.Risk == RiskLevel.Low).ToList();
            var infos = results.Where(r => r.Risk == RiskLevel.Info && !string.IsNullOrEmpty(r.RiskReason)).ToList();

            foreach (var dr in criticals) Output.PrintResult(dr);

            if (!criticalOnly)
            {
                foreach (var dr in highs) Output.PrintResult(dr);

                if (!highAndAbove)
                {
                    foreach (var dr in mediums) Output.PrintResult(dr);

                    if (lows.Count > 0)
                    {
                        Console.WriteLine();
                        Output.PrintProgress($"Low-risk findings ({lows.Count}):");
                        foreach (var dr in lows) Output.PrintResult(dr);
                    }

                    if (verbose && infos.Count > 0)
                    {
                        Console.WriteLine();
                        Output.PrintProgress($"Info findings ({infos.Count}):");
                        foreach (var dr in infos) Output.PrintResult(dr);
                    }
                    else if (infos.Count > 0 && !noWhitelist)
                    {
                        Console.WriteLine();
                        int wl = infos.Count(i => i.IsWhitelisted);
                        if (wl > 0)
                            Output.PrintProgress($"Whitelisted drivers: {wl} (use --no-whitelist to analyze, --verbose to list)");
                    }
                }
            }

            // Exploitable recap
            var loadedExploitable = results
                .Where(r => r.IsLoaded && (r.Risk == RiskLevel.Critical || r.Risk == RiskLevel.High))
                .OrderByDescending(r => r.Risk)
                .ThenByDescending(r => r.LolMatch != null)
                .ToList();

            Output.PrintExploitableRecap(loadedExploitable);

            // Calculate summary
            var summary = new ScanSummary
            {
                TotalScanned = results.Count,
                WhitelistedCount = results.Count(r => r.IsWhitelisted && r.LolMatch == null),
                CurrentlyLoaded = results.Count(r => r.IsLoaded),
                LolDriversMatches = results.Count(r => r.LolMatch != null),
                MsBlocklistMatches = results.Count(r => r.BlocklistMatch != null),
                IoctlFamilyMatches = results.Count(r => r.FamilyMatch != null),
                CompromisedCertMatches = results.Count(r => r.CertFlag != null && r.CertFlag.IsCompromised),
                KnownVulnVendorMatches = results.Count(r => r.VendorMatch != null),
                IoctlReachableConfirmed = results.Sum(r =>
                    r.DangerousImports.Count(i => i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect)),
                TaintedParams = results.Sum(r =>
                    r.DangerousImports.Count(i => i.Taint == TaintStatus.Tainted || i.Taint == TaintStatus.LikelyTainted)),
                UnreachableFpReduced = results.Count(r =>
                    r.DangerousImports.Count > 0 && r.DangerousImports.All(i => i.Reachability == Reachability.NotReachable)),
                CouldNotDetermine = results.Count(r =>
                    r.DangerousImports.Count > 0 && r.DangerousImports.Any(i => i.Reachability == Reachability.Unknown) &&
                    !r.DangerousImports.Any(i => i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect)),
                CriticalCount = criticals.Count,
                HighCount = highs.Count,
                MediumCount = mediums.Count,
                LowCount = lows.Count,
                MissingAslr = results.Count(r => r.Mitigations != null && !r.Mitigations.HasASLR && !r.IsWhitelisted),
                MissingCfg = results.Count(r => r.Mitigations != null && !r.Mitigations.HasCFG && !r.IsWhitelisted),
                RwxSections = results.Sum(r => r.Sections.Count(s => s.IsRWX)),
                HighEntropySections = results.Sum(r => r.Sections.Count(s => s.IsHighEntropy)),
                Unsigned = results.Count(r => !r.IsSigned && string.IsNullOrEmpty(r.Error) && !r.IsWhitelisted),
                BehaviorB14Count = results.Count(r => r.Behaviors.HasFlag(BehaviorTag.B14_UnsafeRtlQueryRegistry)),
                SystemStatus = sysStatus,
                ScanPaths = scanPaths,
            };

            // Compute behavior counts
            var behaviorDefs = new[]
            {
                new { Tag = BehaviorTag.B1_ProtectedServiceTermination, Name = "B1:SvcTermination" },
                new { Tag = BehaviorTag.B2_PrivilegedHandleLeak,       Name = "B2:HandleLeak" },
                new { Tag = BehaviorTag.B3_UnsafePoolAllocation,       Name = "B3:PoolAlloc" },
                new { Tag = BehaviorTag.B4_DynamicKernelCodeExec,      Name = "B4:KernelExec" },
                new { Tag = BehaviorTag.B5_MismatchedMemoryMapping,    Name = "B5:MemMap" },
                new { Tag = BehaviorTag.B6_CodeIntegrityTampering,     Name = "B6:CITamper" },
                new { Tag = BehaviorTag.B7_RemoteHandleClosure,        Name = "B7:HandleClose" },
                new { Tag = BehaviorTag.B8_ArbitraryMemoryWrite,       Name = "B8:MemWrite" },
                new { Tag = BehaviorTag.B9_ArbitraryMsrWrite,          Name = "B9:MsrWrite" },
                new { Tag = BehaviorTag.B10_ArbitraryPortIO,           Name = "B10:PortIO" },
                new { Tag = BehaviorTag.B11_PhysicalMemoryMapping,     Name = "B11:PhysMemMap" },
                new { Tag = BehaviorTag.B12_TaintedKernelArgs,         Name = "B12:TaintedArgs" },
                new { Tag = BehaviorTag.B13_ExecWritableRemap,         Name = "B13:ExecRemap" },
                new { Tag = BehaviorTag.B14_UnsafeRtlQueryRegistry,    Name = "B14:UnsafeRegQuery" },
                new { Tag = BehaviorTag.B15_RtlQueryRegistryTampering, Name = "B15:RegTamper" },
            };
            foreach (var bd in behaviorDefs)
            {
                int count = results.Count(r => r.Behaviors.HasFlag(bd.Tag));
                if (count > 0)
                    summary.BehaviorCounts[bd.Name] = count;
            }

            Output.PrintSummary(summary);

            // Export
            if (jsonOut || (exportPath != null && exportPath.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
            {
                string path = exportPath ?? Path.Combine(Environment.CurrentDirectory, "BYOVDHunter_report.json");
                try { Output.ExportJson(results, summary, path); Output.PrintProgress($"JSON report: {path}"); }
                catch (Exception ex) { Output.PrintWarning($"JSON export failed: {ex.Message}"); }
            }

            if (csvOut || (exportPath != null && exportPath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)))
            {
                string path = exportPath ?? Path.Combine(Environment.CurrentDirectory, "BYOVDHunter_report.csv");
                try { Output.ExportCsv(results, path); Output.PrintProgress($"CSV report: {path}"); }
                catch (Exception ex) { Output.PrintWarning($"CSV export failed: {ex.Message}"); }
            }

            return criticals.Count > 0 ? 1 : 0;
        }

        private static bool HasFlag(string[] args, string flag)
        {
            return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        }

        private static string GetArgValue(string[] args, string flag)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            }
            return null;
        }
    }
}
