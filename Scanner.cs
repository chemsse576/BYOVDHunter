using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace BYOVDHunter
{
    public static class Scanner
    {
        #region Dangerous Import Database

        private static readonly Dictionary<string, (string Category, string Description)> DangerousImportDb =
            new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase)
        {
            // Physical memory access
            {"MmMapIoSpace", ("PhysMem", "Map physical memory to virtual address")},
            {"MmMapIoSpaceEx", ("PhysMem", "Map physical memory to virtual address (extended)")},
            {"MmMapLockedPages", ("PhysMem", "Map locked pages to user/kernel space")},
            {"MmMapLockedPagesSpecifyCache", ("PhysMem", "Map locked pages with cache type")},
            {"MmCopyMemory", ("PhysMem", "Copy arbitrary physical/virtual memory")},
            {"MmGetPhysicalAddress", ("PhysMem", "Translate virtual to physical address")},
            {"ZwMapViewOfSection", ("PhysMem", "Map section into process address space")},
            {"NtMapViewOfSection", ("PhysMem", "Map section into process address space")},
            {"MmMapViewInSystemSpace", ("PhysMem", "Map view in system space")},

            // Process manipulation (EDR killer)
            {"ZwTerminateProcess", ("ProcKill", "Terminate any process")},
            {"NtTerminateProcess", ("ProcKill", "Terminate any process")},
            {"ZwOpenProcess", ("ProcManip", "Open handle to any process")},
            {"NtOpenProcess", ("ProcManip", "Open handle to any process")},
            {"ZwWriteVirtualMemory", ("ProcManip", "Write to process memory")},
            {"NtWriteVirtualMemory", ("ProcManip", "Write to process memory")},
            {"ZwReadVirtualMemory", ("ProcManip", "Read process memory")},
            {"NtReadVirtualMemory", ("ProcManip", "Read process memory")},
            {"ZwAllocateVirtualMemory", ("ProcManip", "Allocate memory in process")},
            {"NtAllocateVirtualMemory", ("ProcManip", "Allocate memory in process")},
            {"ZwProtectVirtualMemory", ("ProcManip", "Change memory protections")},
            {"NtProtectVirtualMemory", ("ProcManip", "Change memory protections")},
            {"PsLookupProcessByProcessId", ("ProcManip", "Resolve process from PID")},
            {"KeAttachProcess", ("ProcManip", "Attach to process context")},
            {"KeStackAttachProcess", ("ProcManip", "Attach to process context (stack)")},
            {"ObOpenObjectByPointer", ("ProcManip", "Get handle from kernel object")},
            {"PsSuspendProcess", ("ProcManip", "Suspend process (stealth EDR kill)")},

            // Token/privilege manipulation
            {"PsReferencePrimaryToken", ("TokenManip", "Access process token")},
            {"PsImpersonateClient", ("TokenManip", "Impersonate caller")},
            {"SeCreateAccessState", ("TokenManip", "Create access state")},
            {"SeCaptureSubjectContext", ("TokenManip", "Capture security context")},

            // Kernel callback manipulation (EDR blinding)
            {"PsSetCreateProcessNotifyRoutine", ("CallbackReg", "Register/unregister process callbacks")},
            {"PsSetCreateProcessNotifyRoutineEx", ("CallbackReg", "Register/unregister process callbacks (Ex)")},
            {"PsSetCreateThreadNotifyRoutine", ("CallbackReg", "Register/unregister thread callbacks")},
            {"PsSetCreateThreadNotifyRoutineEx", ("CallbackReg", "Register/unregister thread callbacks (Ex)")},
            {"PsSetLoadImageNotifyRoutine", ("CallbackReg", "Register/unregister image load callbacks")},
            {"PsSetLoadImageNotifyRoutineEx", ("CallbackReg", "Register/unregister image load callbacks (Ex)")},
            {"CmRegisterCallback", ("CallbackReg", "Register registry callback")},
            {"CmRegisterCallbackEx", ("CallbackReg", "Register registry callback (Ex)")},
            {"CmUnRegisterCallback", ("CallbackUnreg", "UNREGISTER registry callback - can blind EDR")},
            {"ObRegisterCallbacks", ("CallbackReg", "Register object callbacks")},
            {"ObUnRegisterCallbacks", ("CallbackUnreg", "UNREGISTER object callbacks - can blind EDR")},
            {"FltUnregisterFilter", ("CallbackUnreg", "Unregister minifilter - can blind filesystem EDR")},

            // I/O port access (firmware/BIOS)
            {"READ_PORT_UCHAR", ("IoPort", "Read I/O port (byte)")},
            {"READ_PORT_USHORT", ("IoPort", "Read I/O port (word)")},
            {"READ_PORT_ULONG", ("IoPort", "Read I/O port (dword)")},
            {"WRITE_PORT_UCHAR", ("IoPort", "Write I/O port (byte)")},
            {"WRITE_PORT_USHORT", ("IoPort", "Write I/O port (word)")},
            {"WRITE_PORT_ULONG", ("IoPort", "Write I/O port (dword)")},

            // MSR access
            {"__readmsr", ("MSR", "Read Model Specific Register")},
            {"__writemsr", ("MSR", "Write Model Specific Register")},
            {"HalSetBusDataByOffset", ("MSR", "Write to PCI config space")},

            // Handle closure (remote handle disruption)
            {"ZwClose", ("HandleClose", "Close object handle")},

            // Registry from kernel
            {"RtlQueryRegistryValues", ("RegQuery", "Query registry values (potential stack buffer overflow)")},
            {"ZwSetValueKey", ("Registry", "Modify registry value")},
            {"ZwDeleteValueKey", ("Registry", "Delete registry value")},
            {"ZwCreateKey", ("Registry", "Create registry key")},
            {"ZwDeleteKey", ("Registry", "Delete registry key")},

            // File system from kernel
            {"ZwCreateFile", ("FileSystem", "Kernel-level file create/open")},
            {"ZwWriteFile", ("FileSystem", "Kernel-level file write")},
            {"ZwDeleteFile", ("FileSystem", "Kernel-level file delete")},
            {"IoCreateFileEx", ("FileSystem", "Create/open file (extended)")},

            // Device creation
            {"IoCreateDevice", ("Device", "Create device object (potential IOCTL endpoint)")},
            {"IoCreateSymbolicLink", ("Device", "Create symbolic link (userland-accessible name)")},
        };

        public static List<DangerousImport> FindDangerousImports(byte[] data)
        {
            var imports = PeParser.GetImportedFunctions(data);
            var result = new List<DangerousImport>();
            foreach (string fn in imports)
            {
                if (DangerousImportDb.TryGetValue(fn, out var info))
                {
                    result.Add(new DangerousImport
                    {
                        FunctionName = fn,
                        Category = info.Category,
                        Description = info.Description
                    });
                }
            }
            return result;
        }

        public static HashSet<string> GetDangerousImportNames()
        {
            return new HashSet<string>(DangerousImportDb.Keys, StringComparer.OrdinalIgnoreCase);
        }

        #endregion

        #region Whitelist

        private static bool _whitelistEnabled = true;

        private static readonly HashSet<string> CoreWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "acpi.sys","ntoskrnl.exe","ntkrnlmp.exe","ntkrnlpa.exe","ntkrpamp.exe",
            "hal.dll","halmacpi.dll","halacpi.dll","ci.dll",
            "classpnp.sys","disk.sys","volmgr.sys","fltmgr.sys",
            "ndis.sys","tcpip.sys","storport.sys","wdf01000.sys",
            "fwpkclnt.sys","ksecdd.sys","cng.sys",
            "partmgr.sys","pci.sys","ntfs.sys","refs.sys","npfs.sys","msrpc.sys",
            "iorate.sys","volsnap.sys","mountmgr.sys",
            "afd.sys","http.sys","srv2.sys","mrxsmb.sys","mrxsmb20.sys",
            "rdbss.sys","netbt.sys","pacer.sys","dfsc.sys","bowser.sys",
            "dxgkrnl.sys","dxgmms1.sys","dxgmms2.sys",
            "win32k.sys","win32kfull.sys","win32kbase.sys","win32ksg.sys",
            "clfs.sys","ks.sys","portcls.sys",
            "usbhub3.sys","usbxhci.sys","ucx01000.sys","usbccgp.sys","usbehci.sys","usbohci.sys",
            "hdaudio.sys","hdaudbus.sys",
            "intelppm.sys","amdppm.sys","processr.sys",
            "vhdmp.sys","vmswitch.sys","hvax64.sys","hvsocket.sys",
            "winhv.sys","winhvr.sys","vmbus.sys","vmbkmcl.sys",
            "bindflt.sys","wcifs.sys","luafv.sys","fileinfo.sys","wof.sys",
            "cldflt.sys","mpsdrv.sys","mrxdav.sys","lxss.sys",
            "nsiproxy.sys","tdx.sys","netio.sys","wfplwfs.sys",
            "tm.sys","pcw.sys","msisadrv.sys","tpm.sys",
            "wdfilter.sys","wdnisdrv.sys",
            "clipsp.sys",
            "spaceport.sys","stornvme.sys","storahci.sys",
            "bam.sys","dam.sys","cdrom.sys","i8042prt.sys","kbdhid.sys",
            "mouclass.sys","mouhid.sys","mssmbios.sys","bthport.sys",
            "csc.sys","rdpdr.sys","tdi.sys","wanarp.sys",
            "hvservice.sys","vmgid.sys","vpci.sys",
            "ahcache.sys","kbdclass.sys","hidclass.sys",
            "hvsocketcontrol.sys","WUDFRd.sys",
            "bfs.sys","bfsvc.sys","cdfs.sys","exfat.sys","fastfat.sys","udfs.sys",
            "ndisuio.sys","wfplwf.sys","vwififlt.sys","vwifimp.sys",
            "condrv.sys","crashdmp.sys","dumpfve.sys","dump_storport.sys",
            "dump_stornvme.sys","dump_storahci.sys",
            "BasicDisplay.sys","BasicRender.sys","monitor.sys",
            "Ndu.sys","mslldp.sys","lltdio.sys","rspndr.sys",
            "wdiwifi.sys","mwlu97w8x64.sys",
            "VerifierExt.sys","watchdog.sys","wmilib.sys",
            "EhStorClass.sys","SgrmAgent.sys","sgrmagent.sys",
        };

        public static void SetWhitelistEnabled(bool enabled) { _whitelistEnabled = enabled; }

        public static bool IsWhitelisted(string fileName, string signerName, string filePath)
        {
            if (!_whitelistEnabled) return false;
            if (string.IsNullOrEmpty(fileName)) return false;
            if (!CoreWhitelist.Contains(fileName)) return false;

            if (!string.IsNullOrEmpty(signerName))
            {
                string lower = signerName.ToLowerInvariant();
                bool isMsSigned = lower.Contains("microsoft windows") ||
                                  lower.Contains("microsoft corporation") ||
                                  lower.Contains("catalog-signed");
                if (!isMsSigned) return false;
            }

            if (!string.IsNullOrEmpty(filePath))
            {
                string dir = Path.GetDirectoryName(filePath)?.ToLowerInvariant() ?? "";
                if (!dir.Contains(@"\windows\system32")) return false;
            }

            return true;
        }

        public static bool IsWhitelistedNameOnly(string fileName)
        {
            return _whitelistEnabled && CoreWhitelist.Contains(fileName);
        }

        #endregion

        #region Behavior Mapping

        private static readonly Dictionary<string, BehaviorTag> CategoryToBehavior =
            new Dictionary<string, BehaviorTag>(StringComparer.OrdinalIgnoreCase)
        {
            {"ProcKill",      BehaviorTag.B1_ProtectedServiceTermination},
            {"ProcManip",     BehaviorTag.B1_ProtectedServiceTermination},
            {"HandleLeak",    BehaviorTag.B2_PrivilegedHandleLeak},
            {"PoolAlloc",     BehaviorTag.B3_UnsafePoolAllocation},
            {"KernelExec",    BehaviorTag.B4_DynamicKernelCodeExec},
            {"MemMap",        BehaviorTag.B5_MismatchedMemoryMapping},
            {"PhysMem",       BehaviorTag.B8_ArbitraryMemoryWrite | BehaviorTag.B11_PhysicalMemoryMapping},
            {"CITamper",      BehaviorTag.B6_CodeIntegrityTampering},
            {"HandleClose",   BehaviorTag.B7_RemoteHandleClosure},
            {"MSR",           BehaviorTag.B9_ArbitraryMsrWrite},
            {"IoPort",        BehaviorTag.B10_ArbitraryPortIO},
            {"TaintedArgs",   BehaviorTag.B12_TaintedKernelArgs},
            {"MemRemap",      BehaviorTag.B13_ExecWritableRemap},
            {"RegQuery",      BehaviorTag.B14_UnsafeRtlQueryRegistry},
            {"CallbackUnreg", BehaviorTag.B6_CodeIntegrityTampering},
            {"TokenManip",    BehaviorTag.B2_PrivilegedHandleLeak},
        };

        #endregion

        #region Driver Discovery

        public static List<string> DiscoverDriverPaths(string extraScanPath, bool scanDriverStore)
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string sys32Drivers = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
            string sys32 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

            AddDriversFromDir(paths, sys32Drivers);

            try
            {
                foreach (string f in Directory.GetFiles(sys32, "*.sys", SearchOption.TopDirectoryOnly))
                    paths.Add(f);
            }
            catch { }

            AddDriversFromRegistry(paths);

            if (scanDriverStore)
            {
                string driverStore = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "DriverStore", "FileRepository");
                if (Directory.Exists(driverStore))
                {
                    try
                    {
                        foreach (string f in Directory.GetFiles(driverStore, "*.sys", SearchOption.AllDirectories))
                            paths.Add(f);
                    }
                    catch { }
                }
            }

            if (!string.IsNullOrEmpty(extraScanPath) && Directory.Exists(extraScanPath))
                AddDriversFromDir(paths, extraScanPath);

            return paths.ToList();
        }

        private static void AddDriversFromDir(HashSet<string> paths, string dir)
        {
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*.sys", SearchOption.TopDirectoryOnly))
                    paths.Add(f);
            }
            catch { }
        }

        private static void AddDriversFromRegistry(HashSet<string> paths)
        {
            try
            {
                using (var services = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services"))
                {
                    if (services == null) return;
                    foreach (string svcName in services.GetSubKeyNames())
                    {
                        try
                        {
                            using (var svc = services.OpenSubKey(svcName))
                            {
                                if (svc == null) continue;
                                object typeObj = svc.GetValue("Type");
                                if (typeObj == null) continue;
                                int type = Convert.ToInt32(typeObj);
                                if (type != 1 && type != 2) continue;

                                string imagePath = svc.GetValue("ImagePath") as string;
                                if (string.IsNullOrEmpty(imagePath)) continue;
                                imagePath = imagePath.Trim();

                                if (imagePath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                                    imagePath = Path.Combine(
                                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                                        imagePath.Substring(12));
                                else if (imagePath.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) ||
                                         imagePath.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
                                    imagePath = Path.Combine(
                                        Environment.GetFolderPath(Environment.SpecialFolder.Windows), imagePath);
                                else if (imagePath.StartsWith(@"\??\"))
                                    imagePath = imagePath.Substring(4);
                                else if (imagePath.StartsWith(@"\\?\"))
                                    imagePath = imagePath.Substring(4);

                                if (File.Exists(imagePath) &&
                                    imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                                    paths.Add(imagePath);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Loaded Drivers

        public static HashSet<string> GetLoadedDriverBaseNames()
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                int needed = 0;
                EnumDeviceDrivers(null, 0, out needed);
                if (needed <= 0) return names;
                IntPtr[] addrs = new IntPtr[needed / IntPtr.Size];
                if (!EnumDeviceDrivers(addrs, needed, out _)) return names;
                var sb = new StringBuilder(260);
                foreach (var addr in addrs)
                {
                    if (addr == IntPtr.Zero) continue;
                    sb.Clear();
                    if (GetDeviceDriverBaseName(addr, sb, sb.Capacity) > 0)
                        names.Add(sb.ToString());
                }
            }
            catch { }
            return names;
        }

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumDeviceDrivers([Out] IntPtr[] lpImageBase, int cb, out int lpcbNeeded);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetDeviceDriverBaseName(IntPtr ImageBase, StringBuilder lpBaseName, int nSize);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetDeviceDriverFileName(IntPtr ImageBase, StringBuilder lpFileName, int nSize);

        public static Dictionary<string, string> GetLoadedDriverFullPaths()
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                int needed = 0;
                EnumDeviceDrivers(null, 0, out needed);
                if (needed <= 0) return result;
                IntPtr[] addrs = new IntPtr[needed / IntPtr.Size];
                if (!EnumDeviceDrivers(addrs, needed, out _)) return result;
                var sbName = new StringBuilder(260);
                var sbPath = new StringBuilder(260);
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                foreach (var addr in addrs)
                {
                    if (addr == IntPtr.Zero) continue;
                    sbName.Clear();
                    if (GetDeviceDriverBaseName(addr, sbName, sbName.Capacity) <= 0) continue;
                    string baseName = sbName.ToString();

                    sbPath.Clear();
                    if (GetDeviceDriverFileName(addr, sbPath, sbPath.Capacity) > 0)
                    {
                        string fullPath = NormalizeKernelPath(sbPath.ToString(), winDir);
                        if (!string.IsNullOrEmpty(fullPath) && File.Exists(fullPath))
                        {
                            if (!result.ContainsKey(baseName))
                                result[baseName] = fullPath;
                        }
                    }
                }
            }
            catch { }
            return result;
        }

        private static string NormalizeKernelPath(string kernelPath, string winDir)
        {
            if (string.IsNullOrEmpty(kernelPath)) return null;

            if (kernelPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                return Path.Combine(winDir, kernelPath.Substring(12));
            if (kernelPath.StartsWith(@"\??\"))
                return kernelPath.Substring(4);
            if (kernelPath.StartsWith(@"\\?\"))
                return kernelPath.Substring(4);
            if (kernelPath.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
                return Path.Combine(winDir, kernelPath);

            if (kernelPath.Length >= 3 && kernelPath[1] == ':')
                return kernelPath;

            return null;
        }

        #endregion

        #region Signature Verification

        public static void CheckSignature(string filePath,
            out bool isSigned, out bool isValid, out string signerName)
        {
            isSigned = false; isValid = false; signerName = "";
            try
            {
                Guid actionId = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                    pcwszFilePath = filePath
                };
                IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = fileInfoPtr,
                    dwStateAction = 0,
                    dwProvFlags = 0
                };

                int hr = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);
                Marshal.FreeHGlobal(fileInfoPtr);

                if (hr == 0) { isSigned = true; isValid = true; }
                else if (hr == unchecked((int)0x800B0101)) { isSigned = true; isValid = false; }

                if (isSigned)
                {
                    try
                    {
                        var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                        signerName = cert.GetNameInfo(X509NameType.SimpleName, false);
                    }
                    catch { signerName = "(embedded)"; }
                }

                if (!isSigned)
                {
                    bool catSigned = CheckCatalogSignature(filePath, out string catSigner);
                    if (catSigned)
                    {
                        isSigned = true; isValid = true;
                        signerName = !string.IsNullOrEmpty(catSigner) ? catSigner : "(catalog-signed)";
                    }
                }
            }
            catch { }
        }

        private static bool CheckCatalogSignature(string filePath, out string signerName)
        {
            signerName = "";
            IntPtr catAdmin = IntPtr.Zero;
            try
            {
                Guid subsystem = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
                if (!CryptCATAdminAcquireContext(ref catAdmin, ref subsystem, 0)) return false;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int hashSize = 0;
                    CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(),
                        ref hashSize, IntPtr.Zero, 0);
                    if (hashSize <= 0) return false;
                    IntPtr hashPtr = Marshal.AllocHGlobal(hashSize);
                    try
                    {
                        if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(),
                            ref hashSize, hashPtr, 0)) return false;
                        IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(
                            catAdmin, hashPtr, hashSize, 0, IntPtr.Zero);
                        if (catInfo != IntPtr.Zero)
                        {
                            CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                            signerName = "(catalog-signed)";
                            return true;
                        }
                    }
                    finally { Marshal.FreeHGlobal(hashPtr); }
                }
            }
            catch { }
            finally { if (catAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(catAdmin, 0); }
            return false;
        }

        #endregion

        #region Deep Analysis

        public static void DeepAnalysis(DriverResult dr, byte[] data, bool skipTaint = false)
        {
            try
            {
                var deviceNames = PeParser.FindDeviceNames(data);
                foreach (string dn in deviceNames)
                {
                    var di = new DeviceInfo { DeviceName = dn };
                    if (dn.StartsWith("\\DosDevices\\") || dn.StartsWith("\\\\.\\"))
                        di.SymbolicLink = dn;
                    dr.Devices.Add(di);
                }

                var sddlStrings = PeParser.FindSddlStrings(data);
                if (sddlStrings.Count > 0 && dr.Devices.Count > 0)
                    dr.Devices[0].SddlAccess = ParseSddlAccess(sddlStrings[0]);

                var rawIoctlCodes = PeParser.FindIoctlCodes(data);

                var headers = PeParser.ParseHeaders(data);
                if (headers != null)
                {
                    var iatMap = PeParser.GetImportAddressTable(data);
                    var dangerousNames = new HashSet<string>(
                        dr.DangerousImports.Select(i => i.FunctionName), StringComparer.OrdinalIgnoreCase);

                    var dispResult = DispatchAnalyzer.Analyze(data, headers.Value, iatMap, dangerousNames);
                    dr.Dispatch = dispResult;

                    if (dispResult.ExtractedIoctlCodes.Count > 0)
                        foreach (uint c in dispResult.ExtractedIoctlCodes)
                            if (!rawIoctlCodes.Contains(c)) rawIoctlCodes.Add(c);

                    if (dispResult.DeviceControlHandlerRva != 0 && dangerousNames.Count > 0)
                    {
                        var reachability = DispatchAnalyzer.AnalyzeReachability(
                            data, headers.Value, dispResult.DeviceControlHandlerRva, iatMap, dangerousNames);

                        foreach (var imp in dr.DangerousImports)
                        {
                            if (reachability.TryGetValue(imp.FunctionName, out var reach))
                            {
                                imp.Reachability = reach;
                                if (!skipTaint && (reach == Reachability.Direct || reach == Reachability.Indirect))
                                {
                                    var sites = FindImportCallSites(data, headers.Value, iatMap, imp.FunctionName);
                                    if (sites.Count > 0)
                                        imp.Taint = DispatchAnalyzer.AnalyzeTaint(data, sites[0], headers.Value);
                                }
                            }
                        }
                    }

                    bool hasSecureCreate = iatMap.Values.Any(v =>
                        v.Equals("IoCreateDeviceSecureCreate", StringComparison.OrdinalIgnoreCase) ||
                        v.Equals("WdmlibIoCreateDeviceSecure", StringComparison.OrdinalIgnoreCase));
                    if (hasSecureCreate && dr.Devices.Count > 0)
                        dr.Devices[0].HasSecureOpen = true;
                }

                foreach (uint code in rawIoctlCodes.Take(20))
                    dr.IoctlCodes.Add(IoctlInfo.Decode(code));

                dr.SuspiciousStrings = PeParser.FindSuspiciousStrings(data);

                // Compute behavior tags from reachable dangerous imports
                BehaviorTag behaviors = BehaviorTag.None;
                foreach (var imp in dr.DangerousImports)
                {
                    if (imp.Reachability == Reachability.Direct || imp.Reachability == Reachability.Indirect)
                    {
                        if (CategoryToBehavior.TryGetValue(imp.Category, out var bt))
                        {
                            imp.BehaviorTag = bt;
                            behaviors |= bt;
                        }
                        if (imp.Taint == TaintStatus.Tainted || imp.Taint == TaintStatus.LikelyTainted)
                        {
                            behaviors |= BehaviorTag.B12_TaintedKernelArgs;
                        }
                    }
                }

                // B6 heuristic: CITamper import reachable OR suspicious strings + PhysMem reachable
                if (behaviors.HasFlag(BehaviorTag.B6_CodeIntegrityTampering) ||
                    (dr.SuspiciousStrings.Any(s => s == "g_CiEnabled" || s == "g_CiOptions") &&
                     dr.DangerousImports.Any(i => i.Category == "PhysMem" &&
                         (i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect))))
                {
                    behaviors |= BehaviorTag.B6_CodeIntegrityTampering;
                }

                // B14 detection: requires IOCTL reachability + stack buffer pattern
                if (headers != null && dr.DangerousImports.Any(i =>
                    i.FunctionName == "RtlQueryRegistryValues" &&
                    (i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect)))
                {
                    var iatMap2 = PeParser.GetImportAddressTable(data);
                    if (DetectUnsafeRtlQueryRegistry(data, headers.Value, iatMap2))
                        behaviors |= BehaviorTag.B14_UnsafeRtlQueryRegistry;
                }

                // Refine B8 for MmMapLockedPagesSpecifyCache: check AccessMode parameter
                if (behaviors.HasFlag(BehaviorTag.B8_ArbitraryMemoryWrite) && headers != null)
                {
                    var reachablePhysMem = dr.DangerousImports.FindAll(i =>
                        i.Category == "PhysMem" &&
                        (i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect));
                    if (reachablePhysMem.Count > 0 &&
                        reachablePhysMem.TrueForAll(i => i.FunctionName == "MmMapLockedPagesSpecifyCache"))
                    {
                        var iatMap3 = PeParser.GetImportAddressTable(data);
                        uint hRva = dr.Dispatch != null ? dr.Dispatch.DeviceControlHandlerRva : 0;
                        if (!HasUserModeMapping(data, headers.Value, iatMap3, hRva))
                            behaviors &= ~BehaviorTag.B8_ArbitraryMemoryWrite;
                    }
                }

                dr.Behaviors = behaviors;
            }
            catch { }
        }

        private static List<int> FindImportCallSites(byte[] data, PeParser.PeHeaders headers,
            Dictionary<uint, string> iatMap, string importName)
        {
            var sites = new List<int>();
            uint iatRva = 0;
            foreach (var kv in iatMap)
            {
                if (kv.Value.Equals(importName, StringComparison.OrdinalIgnoreCase))
                { iatRva = kv.Key; break; }
            }
            if (iatRva == 0) return sites;

            for (int i = 0; i < data.Length - 6; i++)
            {
                if (data[i] == 0xFF && data[i + 1] == 0x15)
                {
                    int disp = BitConverter.ToInt32(data, i + 2);
                    uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                    if (instrRva > 0 && (uint)(instrRva + 6 + disp) == iatRva)
                    {
                        sites.Add(i);
                        if (sites.Count >= 5) break;
                    }
                }
            }
            return sites;
        }

        private static bool DetectUnsafeRtlQueryRegistry(byte[] data, PeParser.PeHeaders headers,
            Dictionary<uint, string> iatMap)
        {
            uint targetIatRva = 0;
            foreach (var kv in iatMap)
            {
                if (kv.Value.Equals("RtlQueryRegistryValues", StringComparison.OrdinalIgnoreCase))
                { targetIatRva = kv.Key; break; }
            }
            if (targetIatRva == 0) return false;

            for (int i = 0; i < data.Length - 6; i++)
            {
                if (data[i] != 0xFF || data[i + 1] != 0x15) continue;
                int disp = BitConverter.ToInt32(data, i + 2);
                uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                if (instrRva == 0) continue;
                if ((uint)(instrRva + 6 + disp) != targetIatRva) continue;

                bool hasStackQueryTable = false;
                int searchStart = Math.Max(0, i - 64);
                for (int j = i - 4; j >= searchStart; j--)
                {
                    if (j + 5 <= data.Length && data[j] == 0x4C && data[j + 1] == 0x8D && data[j + 2] == 0x44 && data[j + 3] == 0x24)
                    { hasStackQueryTable = true; break; }
                    if (j + 8 <= data.Length && data[j] == 0x4C && data[j + 1] == 0x8D && data[j + 2] == 0x84 && data[j + 3] == 0x24)
                    { hasStackQueryTable = true; break; }
                    if (j + 4 <= data.Length && data[j] == 0x4C && data[j + 1] == 0x8D && data[j + 2] == 0x45)
                    { hasStackQueryTable = true; break; }
                    if (j + 7 <= data.Length && data[j] == 0x4C && data[j + 1] == 0x8D && data[j + 2] == 0x85)
                    { hasStackQueryTable = true; break; }
                }

                if (!hasStackQueryTable) continue;

                // Check for DIRECT flag (0x20) and TYPECHECK mitigation (0x100)
                // Search MOV DWORD patterns that set the Flags field
                bool hasDirect = false;
                bool hasTypecheck = false;
                bool anyFlagStore = false;
                int flagSearch = Math.Max(0, i - 128);
                for (int j = flagSearch; j < i; j++)
                {
                    if (j + 7 > data.Length) break;
                    // C7 41 xx imm32 - MOV DWORD [RCX+disp8], imm32
                    // C7 45 xx imm32 - MOV DWORD [RBP+disp8], imm32
                    // C7 44 24 xx imm32 - MOV DWORD [RSP+disp8], imm32
                    // C7 84 24 xx xx xx xx imm32 - MOV DWORD [RSP+disp32], imm32
                    uint flagVal = 0;
                    bool found = false;
                    if (data[j] == 0xC7 && data[j + 1] == 0x41 && j + 7 <= data.Length)
                    { flagVal = BitConverter.ToUInt32(data, j + 3); found = true; }
                    else if (data[j] == 0xC7 && data[j + 1] == 0x45 && j + 7 <= data.Length)
                    { flagVal = BitConverter.ToUInt32(data, j + 3); found = true; }
                    else if (data[j] == 0xC7 && data[j + 1] == 0x44 && data[j + 2] == 0x24 && j + 8 <= data.Length)
                    { flagVal = BitConverter.ToUInt32(data, j + 4); found = true; }
                    else if (data[j] == 0xC7 && data[j + 1] == 0x84 && data[j + 2] == 0x24 && j + 11 <= data.Length)
                    { flagVal = BitConverter.ToUInt32(data, j + 7); found = true; }
                    else if (data[j] == 0xC7 && data[j + 1] == 0x85 && j + 10 <= data.Length)
                    { flagVal = BitConverter.ToUInt32(data, j + 6); found = true; }

                    if (found && flagVal < 0x1000)
                    {
                        anyFlagStore = true;
                        if ((flagVal & 0x20) != 0)
                        {
                            hasDirect = true;
                            if ((flagVal & 0x100) != 0) hasTypecheck = true;
                        }
                    }
                }

                if (hasDirect && !hasTypecheck) return true;
                if (anyFlagStore && !hasDirect) continue;
                if (!anyFlagStore && hasStackQueryTable) return true;
            }
            return false;
        }

        private static bool HasUserModeMapping(byte[] data, PeParser.PeHeaders headers,
            Dictionary<uint, string> iatMap, uint handlerRva)
        {
            uint targetIatRva = 0;
            foreach (var kv in iatMap)
            {
                if (kv.Value.Equals("MmMapLockedPagesSpecifyCache", StringComparison.OrdinalIgnoreCase))
                { targetIatRva = kv.Key; break; }
            }
            if (targetIatRva == 0) return false;

            HashSet<uint> reachableFuncs = null;
            if (handlerRva != 0)
                reachableFuncs = BuildReachableSet(data, headers, handlerRva);

            for (int i = 0; i < data.Length - 6; i++)
            {
                if (data[i] != 0xFF || data[i + 1] != 0x15) continue;
                int disp = BitConverter.ToInt32(data, i + 2);
                uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                if (instrRva == 0) continue;
                if ((uint)(instrRva + 6 + disp) != targetIatRva) continue;

                if (reachableFuncs != null)
                {
                    uint funcRva = FindFunctionStart(data, headers, i);
                    if (!reachableFuncs.Contains(funcRva)) continue;
                }

                int searchStart = Math.Max(0, i - 32);
                bool kernelMode = false;
                for (int j = i - 2; j >= searchStart; j--)
                {
                    if (j + 2 <= i && (data[j] == 0x31 || data[j] == 0x33) && data[j + 1] == 0xD2)
                    { kernelMode = true; break; }
                    if (j + 5 <= i && data[j] == 0xBA &&
                        data[j + 1] == 0 && data[j + 2] == 0 && data[j + 3] == 0 && data[j + 4] == 0)
                    { kernelMode = true; break; }
                }
                if (!kernelMode) return true;
            }
            return false;
        }

        private static uint FindFunctionStart(byte[] data, PeParser.PeHeaders headers, int offset)
        {
            for (int i = offset - 1; i >= Math.Max(0, offset - 4096); i--)
            {
                if (data[i] == 0xCC && i > 0 && data[i - 1] == 0xCC)
                    return PeParser.OffsetToRva(i + 1, headers.Sections);
            }
            return PeParser.OffsetToRva(offset, headers.Sections);
        }

        private static HashSet<uint> BuildReachableSet(byte[] data, PeParser.PeHeaders headers, uint handlerRva)
        {
            var reachable = new HashSet<uint>();
            reachable.Add(handlerRva);

            int hOff = PeParser.RvaToOffset(handlerRva, headers.Sections);
            if (hOff <= 0) return reachable;

            var depth1 = CollectCallTargets(data, headers, hOff, 0x3000);
            foreach (uint t in depth1) reachable.Add(t);

            foreach (uint t in depth1)
            {
                int tOff = PeParser.RvaToOffset(t, headers.Sections);
                if (tOff <= 0 || tOff >= data.Length) continue;
                foreach (uint t2 in CollectCallTargets(data, headers, tOff, 0x2000))
                    reachable.Add(t2);
            }
            return reachable;
        }

        private static HashSet<uint> CollectCallTargets(byte[] data, PeParser.PeHeaders headers,
            int startOffset, int maxScan)
        {
            var targets = new HashSet<uint>();
            int end = Math.Min(startOffset + maxScan, data.Length - 5);
            for (int i = startOffset; i < end; i++)
            {
                if (data[i] != 0xE8) continue;
                int disp = BitConverter.ToInt32(data, i + 1);
                uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                if (instrRva == 0) continue;
                uint target = (uint)(instrRva + 5 + disp);
                if (target > 0x1000 && target < 0x200000)
                    targets.Add(target);
            }
            return targets;
        }

        #endregion

        #region Risk Assessment

        public static void AssessRisk(DriverResult dr, SystemProtection sysStatus)
        {
            if (dr.IsWhitelisted && dr.LolMatch == null && dr.BlocklistMatch == null)
            {
                dr.Risk = RiskLevel.Info;
                dr.RiskReason = "Whitelisted (Microsoft core driver, signature verified)";
                return;
            }

            bool hasLolOrBlocklist = dr.LolMatch != null || dr.BlocklistMatch != null;
            bool hasDangerousImports = dr.DangerousImports.Count > 0;
            bool hasDeviceExposure = dr.Devices.Count > 0;
            bool hasCompromisedCert = dr.CertFlag != null && dr.CertFlag.IsCompromised;
            bool hasFamilyMatch = dr.FamilyMatch != null;
            bool hasVendorMatch = dr.VendorMatch != null;

            bool hasReachable = dr.DangerousImports.Any(i =>
                i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect);
            bool hasTainted = dr.DangerousImports.Any(i =>
                i.Taint == TaintStatus.Tainted || i.Taint == TaintStatus.LikelyTainted);
            bool allNotReachable = hasDangerousImports && dr.DangerousImports.All(i =>
                i.Reachability == Reachability.NotReachable);

            bool onlyGenericImports = hasDangerousImports &&
                dr.DangerousImports.All(i =>
                    i.FunctionName.Equals("ZwClose", StringComparison.OrdinalIgnoreCase) ||
                    i.FunctionName.Equals("IoCreateDevice", StringComparison.OrdinalIgnoreCase));

            bool hasMethodNeither = dr.IoctlCodes.Any(c => c.Method == 3);
            bool hasAnyAccess = dr.IoctlCodes.Any(c => c.Access == 0);
            bool noChecksOnCreate = dr.Dispatch != null &&
                dr.Dispatch.CreateAccessCheck == AccessCheckVerdict.NoChecks;
            bool noValidation = dr.Dispatch != null &&
                dr.Dispatch.BufferValidation == BufferValidation.NoValidation;
            bool isWdm = dr.Framework == DriverFramework.WDM;
            bool isKmdf = dr.Framework == DriverFramework.KMDF;

            // B14: Unsafe RtlQueryRegistryValues - CVE-2025-8412 pattern
            if (dr.Behaviors.HasFlag(BehaviorTag.B14_UnsafeRtlQueryRegistry) && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "Unsafe RtlQueryRegistryValues (stack buffer overflow pattern) - LOADED";
                dr.Impact = "Kernel stack overflow / Code Integrity bypass / arbitrary code execution";
                dr.ExploitUse = "BYOVD / DSE bypass (CVE-2025-8412 pattern)";
                dr.Note = "RtlQueryRegistryValues with fixed-size stack buffer and RTL_QUERY_REGISTRY_DIRECT. Attacker controls registry value size.";
                return;
            }

            if (dr.Behaviors.HasFlag(BehaviorTag.B14_UnsafeRtlQueryRegistry) && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "Unsafe RtlQueryRegistryValues (stack buffer overflow pattern) - on disk";
                dr.Impact = "Kernel stack overflow / Code Integrity bypass (requires load)";
                dr.ExploitUse = "BYOVD / DSE bypass (CVE-2025-8412 pattern)";
                return;
            }

            // B6: Code Integrity Tampering confirmed
            if (dr.Behaviors.HasFlag(BehaviorTag.B6_CodeIntegrityTampering) && hasReachable && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "Code Integrity tampering path confirmed (g_CiEnabled/g_CiOptions) - LOADED";
                dr.Impact = "DSE bypass / unsigned driver loading / rootkit installation";
                dr.ExploitUse = "BYOVD / DSE bypass";
                return;
            }

            // B4: Dynamic kernel code execution
            if (dr.Behaviors.HasFlag(BehaviorTag.B4_DynamicKernelCodeExec) && hasTainted && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "Dynamic kernel code execution with tainted input - LOADED";
                dr.Impact = "Arbitrary kernel code execution";
                dr.ExploitUse = "BYOVD / kernel shellcode injection";
                return;
            }

            // B7: Remote handle closure
            if (dr.Behaviors.HasFlag(BehaviorTag.B7_RemoteHandleClosure) && hasTainted && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "Remote handle closure with tainted input - LOADED";
                dr.Impact = "EDR handle disruption / file lock bypass";
                dr.ExploitUse = "BYOVD / EDR evasion";
                return;
            }

            // B3: Unsafe pool allocation with no validation
            if (dr.Behaviors.HasFlag(BehaviorTag.B3_UnsafePoolAllocation) && noValidation && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "Unsafe pool allocation with no buffer validation - LOADED";
                dr.Impact = "Kernel pool overflow / privilege escalation";
                dr.ExploitUse = "BYOVD / LPE";
                return;
            }

            // CRITICAL
            if (hasLolOrBlocklist && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = FormatDbMatch(dr) + " - LOADED in kernel";
                dr.Impact = "Known exploitable - check CVE details";
                dr.ExploitUse = "BYOVD";
                if (dr.BlocklistMatch != null && !sysStatus.HvciEnabled)
                    dr.Note = "HVCI is OFF - blocklist NOT enforced";
                return;
            }

            if (hasReachable && hasTainted && hasDeviceExposure && dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "IOCTL path confirmed + tainted input - LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                dr.Note = "Confirmed exploitable. Ready for PoC.";
                return;
            }

            if (hasReachable && hasDeviceExposure && noChecksOnCreate && noValidation &&
                (hasMethodNeither || hasAnyAccess) && dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "Reachable + no checks + no validation + METHOD_NEITHER - LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                dr.Note = "Maximum attack surface. Ready for PoC.";
                return;
            }

            var criticalCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "PhysMem", "ProcKill", "ProcManip", "IoPort", "MSR", "CallbackUnreg" };
            bool physMemDowngraded = dr.Behaviors.HasFlag(BehaviorTag.B11_PhysicalMemoryMapping) &&
                !dr.Behaviors.HasFlag(BehaviorTag.B8_ArbitraryMemoryWrite);
            bool hasReachableCriticalCategory = dr.DangerousImports.Any(i =>
                (i.Reachability == Reachability.Direct || i.Reachability == Reachability.Indirect) &&
                criticalCategories.Contains(i.Category ?? "") &&
                !(physMemDowngraded && i.Category == "PhysMem"));

            if (hasReachableCriticalCategory && hasDeviceExposure && dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.Critical;
                dr.RiskReason = "IOCTL-to-import path confirmed (high-risk category) - LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                dr.Note = "0-day BYOVD candidate. Manual IOCTL reversing recommended.";
                return;
            }

            if (hasReachable && hasDeviceExposure && dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "IOCTL-to-import path confirmed (lower-risk category) - LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                return;
            }

            // HIGH
            if (hasLolOrBlocklist && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = FormatDbMatch(dr) + " - on disk (not loaded)";
                dr.Impact = "Available for drop-and-load BYOVD attack";
                dr.ExploitUse = "BYOVD (requires load)";
                return;
            }

            if (hasReachable && hasDeviceExposure && !dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "IOCTL-to-import path confirmed - on disk";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr) + " (requires load)";
                return;
            }

            if (hasCompromisedCert && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = $"Compromised certificate: {dr.CertFlag.Reason}";
                dr.Impact = "Potentially malicious driver";
                return;
            }

            if (isWdm && hasDangerousImports && noChecksOnCreate && dr.IsLoaded && !dr.IsWhitelisted)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "WDM + dangerous imports + no access checks + LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                return;
            }

            if (hasVendorMatch && hasDangerousImports && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = $"Known vuln vendor ({dr.VendorMatch.VendorName}) + dangerous imports + LOADED";
                dr.Impact = BuildImpactString(dr);
                dr.ExploitUse = BuildExploitUse(dr);
                return;
            }

            if (hasFamilyMatch && dr.IsLoaded)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = $"IOCTL matches {dr.FamilyMatch.FamilyName} + LOADED";
                dr.Impact = dr.FamilyMatch.Description;
                dr.ExploitUse = "BYOVD";
                return;
            }

            // MEDIUM
            if (allNotReachable && hasDangerousImports && !onlyGenericImports)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = "Imports NOT_REACHABLE from IOCTL handler (FP reduced)";
                dr.Note = "Likely internal hardware init use only";
                return;
            }

            if (hasDangerousImports && !onlyGenericImports && !hasDeviceExposure)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = "Dangerous imports but no device exposure found";
                return;
            }

            if (isKmdf && hasDangerousImports && !onlyGenericImports)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = "KMDF driver with dangerous imports (framework protection)";
                return;
            }

            if (hasDangerousImports && !onlyGenericImports && hasDeviceExposure && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = "Dangerous imports + device exposure (not loaded)";
                dr.Impact = BuildImpactString(dr);
                return;
            }

            if (hasCompromisedCert && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = $"Compromised certificate ({dr.CertFlag.Reason}) - not loaded";
                return;
            }

            if (hasFamilyMatch && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = $"IOCTL matches {dr.FamilyMatch.FamilyName} - not loaded";
                return;
            }

            if (hasVendorMatch && hasDangerousImports && !onlyGenericImports && !dr.IsLoaded)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = $"Known vuln vendor ({dr.VendorMatch.VendorName}) - not loaded";
                return;
            }

            // LOW
            if (!dr.IsSigned && !hasDangerousImports)
            {
                dr.Risk = RiskLevel.Low;
                dr.RiskReason = "Unsigned driver, no dangerous imports";
                return;
            }

            if (dr.Metadata != null && dr.Metadata.AgeYears > 10 && !hasDangerousImports)
            {
                dr.Risk = RiskLevel.Low;
                dr.RiskReason = $"Very old driver ({dr.Metadata.CompileDate}), no dangerous imports";
                return;
            }

            if (dr.Mitigations != null && dr.Mitigations.MissingCount >= 2 && !hasDangerousImports)
            {
                dr.Risk = RiskLevel.Low;
                dr.RiskReason = "Missing modern mitigations, no dangerous imports";
                return;
            }

            if (dr.SuspiciousStrings.Count > 0 && !hasDangerousImports)
            {
                dr.Risk = RiskLevel.Low;
                dr.RiskReason = "Suspicious strings found, no dangerous imports";
                return;
            }

            if (dr.VersionInfo != null && (dr.VersionInfo.HasSuspiciousKeywords || dr.VersionInfo.FilenameMismatch))
            {
                dr.Risk = RiskLevel.Low;
                dr.RiskReason = dr.VersionInfo.FilenameMismatch
                    ? "Filename mismatch with OriginalFilename"
                    : "Suspicious keywords in metadata";
                return;
            }

            dr.Risk = RiskLevel.Info;
        }

        public static void DemoteMicrosoftSigned(DriverResult dr)
        {
            if (!dr.IsMicrosoftSigned) return;
            if (dr.LolMatch != null || dr.BlocklistMatch != null) return;

            if (dr.Risk == RiskLevel.Critical)
            {
                dr.Risk = RiskLevel.High;
                dr.RiskReason = "[MS-signed demoted] " + dr.RiskReason;
            }
            else if (dr.Risk == RiskLevel.High)
            {
                dr.Risk = RiskLevel.Medium;
                dr.RiskReason = "[MS-signed demoted] " + dr.RiskReason;
            }
        }

        private static string FormatDbMatch(DriverResult dr)
        {
            var parts = new List<string>();
            if (dr.LolMatch != null) parts.Add("LOLDrivers");
            if (dr.BlocklistMatch != null) parts.Add("MS Blocklist");
            return string.Join(" + ", parts);
        }

        private static string BuildImpactString(DriverResult dr)
        {
            var impacts = new List<string>();
            bool hasMem = dr.DangerousImports.Any(i => i.Category == "PhysMem");
            bool hasProc = dr.DangerousImports.Any(i => i.Category == "ProcKill" || i.Category == "ProcManip");
            bool hasCallbackUnreg = dr.DangerousImports.Any(i => i.Category == "CallbackUnreg");
            bool hasIoPort = dr.DangerousImports.Any(i => i.Category == "IoPort");
            bool hasMsr = dr.DangerousImports.Any(i => i.Category == "MSR");

            if (hasMem) impacts.Add("LPE");
            if (hasMem || hasCallbackUnreg) impacts.Add("EDR bypass");
            if (hasProc) impacts.Add("EDR kill");
            if (hasMem) impacts.Add("credential theft");
            if (hasIoPort || hasMsr) impacts.Add("firmware persistence");
            if (impacts.Count == 0) impacts.Add("potential exploitation");
            return string.Join(" / ", impacts);
        }

        private static string BuildExploitUse(DriverResult dr)
        {
            var uses = new List<string> { "BYOVD" };
            bool hasMem = dr.DangerousImports.Any(i => i.Category == "PhysMem");
            bool hasProc = dr.DangerousImports.Any(i => i.Category == "ProcKill" || i.Category == "ProcManip");
            bool hasCallbackUnreg = dr.DangerousImports.Any(i => i.Category == "CallbackUnreg");

            if (hasProc) uses.Add("EDR killer");
            if (hasCallbackUnreg) uses.Add("EDR blinding");
            if (hasMem) { uses.Add("PPL bypass"); uses.Add("DSE bypass"); }
            uses.Add("persistence");
            return string.Join(" / ", uses);
        }

        private static string ParseSddlAccess(string sddl)
        {
            if (string.IsNullOrEmpty(sddl)) return "";
            if (sddl.Contains("WD")) return "Everyone (no restrictions)";
            if (sddl.Contains("AU")) return "Authenticated Users";
            if (sddl.Contains("BU")) return "Builtin Users";
            if (sddl.Contains("BA") && !sddl.Contains("BU") && !sddl.Contains("WD"))
                return "Administrators only";
            if (sddl.Contains("SY") && !sddl.Contains("BA"))
                return "SYSTEM only";
            return "Custom ACL";
        }

        #endregion

        #region Hashing

        public static string ComputeSha256(string filePath)
        {
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        #endregion

        #region P/Invoke Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
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
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        private static extern bool CryptCATAdminAcquireContext(ref IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref int pcbHash, IntPtr pbHash, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, IntPtr pbHash, int cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        #endregion
    }
}
