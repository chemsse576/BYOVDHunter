using System;
using System.Collections.Generic;
using System.Linq;

namespace BYOVDHunter
{
    public static class VulnDatabase
    {
        #region Known IOCTL Families

        private static readonly List<IoctlFamily> IoctlFamilies = new List<IoctlFamily>
        {
            new IoctlFamily("RTCore64 (MSI Afterburner)", "CVE-2019-16098 - Physical memory R/W", 0x80002000, 0x80002020),
            new IoctlFamily("DBUtil (Dell)", "CVE-2021-21551 - Physical memory R/W, arbitrary kernel R/W", 0x9B0C1EC0, 0x9B0C1F10),
            new IoctlFamily("mhyprot2 (Genshin AntiCheat)", "Kernel R/W + process termination", 0x81034000, 0x81034020),
            new IoctlFamily("HW.sys (CPUID/CPU-Z)", "Physical memory mapping, I/O port access", 0x9C402000, 0x9C402020),
            new IoctlFamily("ProcExp (Process Explorer legacy)", "Process manipulation", 0x8335200C, 0x83352020),
            new IoctlFamily("GDRV (Gigabyte)", "CVE-2018-19320 - Physical memory R/W", 0xC3502000, 0xC3502020),
            new IoctlFamily("WinIO", "I/O port and physical memory access", 0x9C406000, 0x9C406010),
            new IoctlFamily("AsrDrv (ASRock)", "Arbitrary R/W, MSR access", 0xA0406000, 0xA0406020),
            new IoctlFamily("EneIo (ENE Technology)", "Physical memory + I/O port access", 0x80862000, 0x80862010),
            new IoctlFamily("DirectIo (PassMark)", "Physical memory mapping", 0x9C402000, 0x9C402004),
            new IoctlFamily("Capcom.sys", "Intentional backdoor - kernel code execution", 0xAA012044, 0xAA013044),
            new IoctlFamily("Zemana", "Kernel R/W + process manipulation", 0x80002010, 0x80002040),
        };

        public static IoctlFamilyMatch MatchIoctlFamily(IEnumerable<uint> codes)
        {
            foreach (uint code in codes)
            {
                foreach (var family in IoctlFamilies)
                {
                    if (code >= family.RangeStart && code <= family.RangeEnd)
                    {
                        return new IoctlFamilyMatch
                        {
                            FamilyName = family.Name,
                            Description = family.Description,
                            MatchedCode = $"0x{code:X8}"
                        };
                    }
                }
            }
            return null;
        }

        #endregion

        #region Known Vulnerable Vendors

        private static readonly Dictionary<string, string> VulnerableVendors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "micro-star", "MSI - RTCore64, multiple GPU utility drivers" },
            { "msi", "MSI - RTCore64, multiple GPU utility drivers" },
            { "asrock", "ASRock - AsrDrv series" },
            { "gigabyte", "GIGABYTE - GDRV, motherboard utility drivers" },
            { "american megatrends", "AMI - BIOS/UEFI utility drivers" },
            { "capcom", "Capcom - capcom.sys intentional backdoor" },
            { "cpuid", "CPUID - HW.sys (CPU-Z, HWMonitor)" },
            { "passmark", "PassMark - DirectIo" },
            { "zemana", "Zemana - AV drivers with dangerous primitives" },
            { "iobit", "IObit - Utility drivers with dangerous primitives" },
            { "safetica", "Safetica - ProcessMonitorDriver CVE-2026-0828" },
            { "honor", "HONOR - MonProcess.sys CVEs" },
            { "techpowerup", "TechPowerUp - GPU-Z CVE-2019-7245" },
            { "dell", "Dell - DBUtil CVE-2021-21551" },
            { "marvin test", "Marvin Test Solutions - Various vulnerable drivers" },
            { "phoenix", "Phoenix Technologies - BIOS utility drivers" },
            { "ene technology", "ENE Technology - EneIo drivers" },
            { "inpout", "InpOut - I/O port access drivers" },
            { "rweverything", "RWEverything - Full system R/W access" },
            { "cheat engine", "Cheat Engine - dbk64.sys kernel driver" },
            { "speedfan", "SpeedFan - Multiple kernel access primitives" },
            { "razer", "Razer - Multiple privilege escalation drivers" },
            { "corsair", "Corsair - CorsairLLAccess kernel driver" },
            { "evga", "EVGA - EleetCtrl kernel driver" },
            { "biostar", "BIOSTAR - BSMIx64.sys driver" },
        };

        public static VendorMatch MatchVendor(string signerName, string companyName)
        {
            foreach (var name in new[] { signerName, companyName })
            {
                if (string.IsNullOrEmpty(name)) continue;
                string lower = name.ToLowerInvariant();
                foreach (var kv in VulnerableVendors)
                {
                    if (lower.Contains(kv.Key.ToLowerInvariant()))
                    {
                        return new VendorMatch
                        {
                            VendorName = kv.Key,
                            Reason = kv.Value
                        };
                    }
                }
            }
            return null;
        }

        #endregion

        #region MS Vulnerable Driver Blocklist (embedded subset)

        private static readonly HashSet<string> MsBlocklistHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // RTCore64.sys / RTCore32.sys (MSI Afterburner)
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862571c20b5f1112d",
            // DBUtil_2_3.sys (Dell)
            "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
            // HW.sys (CPUID)
            "6a4875ae86f013ea97abc253a3c3b37c4302a8b4b3e9e37a508488f8ab68e2c0",
            // mhyprot2.sys
            "509628b6d16d2428031311d7bd2add8d5f5160e9ecc0cd909f1e82bbbb3234d6",
            // capcom.sys
            "73c98438ac64a68e88b7b0afd11ba140a6e5fb6bef0e305b9006fa37d5bf37eb",
            // gdrv.sys (Gigabyte)
            "31f4cfb4c71da44120752721103a16512e41c4e81563e0c3a39d1e9b63c77e16",
            // AsrDrv106.sys (ASRock)
            "f87e0a28755249f2f3083e39ba0eabb3bc56e14da4a42a05c2e0be5777a5b668",
            // EneIo64.sys
            "174e4e6a1e0e6ce8f53b5ed1a3e4c6054d40a9c8f59e56bce6e4ca93e10b9fb1",
            // WinIO.sys
            "3de3adb8cc2b74b3577f26c01a1bf0ed4c9023ea3bca2c8cf998f52c2bbf0d89",
            // ProcExp152.sys (old Process Explorer)
            "9b54b1f72bcbb50e476da03b76e33f6c429f2eb7f8b9b26e73dbc6e0c8e59e80",
            // speedfan.sys
            "eb1980e7c0d5e5b94d5fcdc5ee2e6e90fccf44bcb97ceaebbd7d0c3f3c8c5ac1",
            // dbk64.sys (Cheat Engine)
            "9cd52f00bf40de tried_4bd84d7a4419b5e403b9c1ba0f4742a2e4ba750c518c",
            // inpoutx64.sys
            "b7fa4dc1e0b800a51498cc91b6e3e826a0d8af0cbc59c3f72eb2dba862c57f33",
        };

        public static MsBlocklistMatch CheckMsBlocklist(string sha256, bool hvciEnabled, bool blocklistEnabled)
        {
            if (string.IsNullOrEmpty(sha256)) return null;
            if (!MsBlocklistHashes.Contains(sha256)) return null;
            return new MsBlocklistMatch
            {
                DriverName = "",
                Description = "Driver hash matches Microsoft Vulnerable Driver Blocklist",
                HvciEnabled = hvciEnabled,
                BlocklistEnabled = blocklistEnabled
            };
        }

        #endregion

        private class IoctlFamily
        {
            public string Name;
            public string Description;
            public uint RangeStart;
            public uint RangeEnd;

            public IoctlFamily(string name, string desc, uint start, uint end)
            {
                Name = name; Description = desc; RangeStart = start; RangeEnd = end;
            }
        }
    }
}
