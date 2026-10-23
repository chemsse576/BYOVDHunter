using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace BYOVDHunter
{
    public static class PeAnalyzer
    {
        public static PeMetadata ExtractMetadata(byte[] data)
        {
            var meta = new PeMetadata();
            var headers = PeParser.ParseHeaders(data);
            if (headers == null) return meta;
            var h = headers.Value;

            meta.TimeDateStamp = h.TimeDateStamp;
            meta.IsPe32Plus = h.IsPe32Plus;
            meta.EntryPointRva = h.EntryPointRva;
            meta.LinkerVersion = $"{h.MajorLinkerVersion}.{h.MinorLinkerVersion}";

            if (h.TimeDateStamp > 0 && h.TimeDateStamp < 0xFFFFFFFF)
            {
                try
                {
                    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    var compileDate = epoch.AddSeconds(h.TimeDateStamp);
                    if (compileDate.Year >= 1990 && compileDate.Year <= 2030)
                    {
                        meta.CompileDate = compileDate.ToString("yyyy-MM-dd");
                        meta.AgeYears = (int)((DateTime.UtcNow - compileDate).TotalDays / 365.25);
                    }
                }
                catch { }
            }

            meta.PdbPath = PeParser.GetPdbPath(data) ?? "";
            return meta;
        }

        public static PeMitigations CheckMitigations(byte[] data)
        {
            var mit = new PeMitigations();
            var headers = PeParser.ParseHeaders(data);
            if (headers == null) return mit;
            ushort dc = headers.Value.DllCharacteristics;

            mit.HasASLR = (dc & 0x0040) != 0;           // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            mit.HasDEP = (dc & 0x0100) != 0;             // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            mit.HasCFG = (dc & 0x4000) != 0;             // IMAGE_DLLCHARACTERISTICS_GUARD_CF
            mit.HasForceIntegrity = (dc & 0x0080) != 0;  // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

            if (!mit.HasASLR) mit.MissingCount++;
            if (!mit.HasDEP) mit.MissingCount++;
            if (!mit.HasCFG) mit.MissingCount++;
            return mit;
        }

        public static List<SectionAnalysis> AnalyzeSections(byte[] data)
        {
            var results = new List<SectionAnalysis>();
            var headers = PeParser.ParseHeaders(data);
            if (headers == null) return results;

            var knownNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".text", ".data", ".rdata", ".rsrc", ".pdata", ".reloc",
                ".bss", "INIT", "PAGE", ".edata", ".idata", ".CRT",
                ".gfids", ".giats", ".00cfg", ".retplne", ".mrdata",
                "PAGEVRFY", "PAGELK", "PAGEDATA", "INITDATA", ".tls",
                "ALMOSTRO", "CACHEALI", ".voltbl", ".didat"
            };

            foreach (var sec in headers.Value.Sections)
            {
                var sa = new SectionAnalysis
                {
                    Name = sec.Name,
                    VirtualAddress = sec.VirtualAddress,
                    VirtualSize = sec.VirtualSize,
                    RawSize = sec.SizeOfRawData,
                    RawOffset = sec.PointerToRawData,
                    Characteristics = sec.Characteristics,
                    IsExecutable = (sec.Characteristics & 0x20000000) != 0,
                    IsWritable = (sec.Characteristics & 0x80000000) != 0,
                };
                sa.IsRWX = sa.IsExecutable && sa.IsWritable;
                sa.IsUnusualName = !knownNames.Contains(sec.Name) &&
                                   !sec.Name.StartsWith("PAGE", StringComparison.OrdinalIgnoreCase);

                if (sec.SizeOfRawData > 0 && sec.PointerToRawData + sec.SizeOfRawData <= data.Length)
                {
                    int start = (int)sec.PointerToRawData;
                    int len = (int)Math.Min(sec.SizeOfRawData, 65536);
                    sa.Entropy = CalculateEntropy(data, start, len);
                    sa.IsHighEntropy = sa.Entropy > 7.0;
                }

                results.Add(sa);
            }
            return results;
        }

        public static VersionInfoData ExtractVersionInfo(string filePath)
        {
            var vi = new VersionInfoData();
            try
            {
                var fvi = FileVersionInfo.GetVersionInfo(filePath);
                vi.CompanyName = fvi.CompanyName ?? "";
                vi.FileDescription = fvi.FileDescription ?? "";
                vi.ProductName = fvi.ProductName ?? "";
                vi.FileVersion = fvi.FileVersion ?? "";
                vi.OriginalFilename = fvi.OriginalFilename ?? "";
                vi.Copyright = fvi.LegalCopyright ?? "";

                string actualName = Path.GetFileName(filePath);
                if (!string.IsNullOrEmpty(vi.OriginalFilename) &&
                    !vi.OriginalFilename.Equals(actualName, StringComparison.OrdinalIgnoreCase))
                    vi.FilenameMismatch = true;

                string combined = $"{vi.FileDescription} {vi.ProductName} {vi.OriginalFilename}".ToLowerInvariant();
                string[] suspiciousKeywords = { "test", "debug", "sample", "example", "poc", "demo", "exploit", "hack" };
                vi.HasSuspiciousKeywords = suspiciousKeywords.Any(k => combined.Contains(k));
            }
            catch { }
            return vi;
        }

        public static DriverFramework DetectFramework(List<string> imports)
        {
            if (imports.Any(i => i.StartsWith("Wdf", StringComparison.OrdinalIgnoreCase) ||
                                 i.Equals("WdfVersionBind", StringComparison.OrdinalIgnoreCase) ||
                                 i.Equals("WdfDriverCreate", StringComparison.OrdinalIgnoreCase)))
                return DriverFramework.KMDF;

            if (imports.Any(i => i == "IoCompleteRequest" || i == "IoGetCurrentIrpStackLocation"))
                return DriverFramework.WDM;

            return DriverFramework.Unknown;
        }

        public static List<string> FindDangerousExports(List<string> exports)
        {
            var dangerousPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "MapPhysicalMemory", "MapIoSpace", "ReadPhysicalMemory", "WritePhysicalMemory",
                "ReadMsr", "WriteMsr", "ReadPort", "WritePort", "ReadPciConfig", "WritePciConfig",
                "MapMemory", "UnmapMemory", "ReadMemory", "WriteMemory",
                "TerminateProcess", "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
            };

            return exports.Where(e => dangerousPatterns.Any(p =>
                e.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
        }

        public static CertificateFlag CheckCertificateFlags(string signerName, int ageYears = 0)
        {
            if (string.IsNullOrEmpty(signerName)) return null;
            string lower = signerName.ToLowerInvariant();

            var alwaysCompromised = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "ht srl", "HackingTeam leak" },
                { "hackingteam", "HackingTeam leak" },
            };

            foreach (var kv in alwaysCompromised)
            {
                if (lower.Contains(kv.Key.ToLowerInvariant()))
                    return new CertificateFlag { Reason = kv.Value, IsCompromised = true };
            }

            // Realtek/JMicron: only flag old drivers (pre-2015) that may use the leaked Stuxnet-era certs
            var stuxnetSigners = new[] { "realtek semiconductor", "jmicron technology" };
            foreach (var signer in stuxnetSigners)
            {
                if (lower.Contains(signer))
                {
                    if (ageYears > 11)
                        return new CertificateFlag { Reason = "Leaked certificate (Stuxnet-era)", IsCompromised = true };
                    return new CertificateFlag { Reason = "Vendor had historical cert leak (Stuxnet); current cert OK", IsCompromised = false };
                }
            }

            string[] testKeywords = { "test", "debug", "sample", "development" };
            if (testKeywords.Any(k => lower.Contains(k)))
                return new CertificateFlag { Reason = "Test/debug certificate detected", IsTestSigned = true };

            return null;
        }

        private static double CalculateEntropy(byte[] data, int start, int length)
        {
            var freq = new int[256];
            int end = Math.Min(start + length, data.Length);
            int total = end - start;
            if (total <= 0) return 0;

            for (int i = start; i < end; i++)
                freq[data[i]]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / total;
                entropy -= p * Math.Log(p, 2);
            }
            return Math.Round(entropy, 2);
        }
    }
}
