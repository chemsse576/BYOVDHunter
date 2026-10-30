using System.Collections.Generic;

namespace BYOVDHunter
{
    public enum RiskLevel { Info, Low, Medium, High, Critical }
    public enum Reachability { Direct, Indirect, NotReachable, Unknown }
    public enum TaintStatus { Tainted, LikelyTainted, NotTainted, Unknown }
    public enum AccessCheckVerdict { NoChecks, HasChecks, Unknown }
    public enum BufferValidation { NoValidation, BasicValidation, ProperValidation, Unknown }
    public enum DriverFramework { Unknown, WDM, KMDF }

    [System.Flags]
    public enum BehaviorTag : int
    {
        None                          = 0,
        B1_ProtectedServiceTermination = 1 << 0,
        B2_PrivilegedHandleLeak       = 1 << 1,
        B3_UnsafePoolAllocation       = 1 << 2,
        B4_DynamicKernelCodeExec      = 1 << 3,
        B5_MismatchedMemoryMapping    = 1 << 4,
        B6_CodeIntegrityTampering     = 1 << 5,
        B7_RemoteHandleClosure        = 1 << 6,
        B8_ArbitraryMemoryWrite       = 1 << 7,
        B9_ArbitraryMsrWrite          = 1 << 8,
        B10_ArbitraryPortIO           = 1 << 9,
        B11_PhysicalMemoryMapping     = 1 << 10,
        B12_TaintedKernelArgs         = 1 << 11,
        B13_ExecWritableRemap         = 1 << 12,
        B14_UnsafeRtlQueryRegistry    = 1 << 13,
        B15_RtlQueryRegistryTampering = 1 << 14,
    }

    public class DriverResult
    {
        public string Path { get; set; }
        public string FileName { get; set; }
        public string Sha256 { get; set; }
        public bool IsSigned { get; set; }
        public bool IsSignatureValid { get; set; }
        public string SignerName { get; set; }
        public bool IsLoaded { get; set; }
        public bool IsWhitelisted { get; set; }
        public string SourceLocation { get; set; }

        public List<DangerousImport> DangerousImports { get; set; }
        public List<string> ExportedDangerousFunctions { get; set; }
        public List<DeviceInfo> Devices { get; set; }
        public List<IoctlInfo> IoctlCodes { get; set; }
        public List<string> SuspiciousStrings { get; set; }

        public LolMatch LolMatch { get; set; }
        public MsBlocklistMatch BlocklistMatch { get; set; }
        public IoctlFamilyMatch FamilyMatch { get; set; }
        public VendorMatch VendorMatch { get; set; }
        public CertificateFlag CertFlag { get; set; }

        public PeMetadata Metadata { get; set; }
        public PeMitigations Mitigations { get; set; }
        public List<SectionAnalysis> Sections { get; set; }
        public VersionInfoData VersionInfo { get; set; }

        public DriverFramework Framework { get; set; }
        public DispatchAnalysisResult Dispatch { get; set; }
        public BehaviorTag Behaviors { get; set; }

        public RiskLevel Risk { get; set; }
        public string RiskReason { get; set; }
        public string Impact { get; set; }
        public string ExploitUse { get; set; }
        public string Note { get; set; }
        public string Error { get; set; }

        public DriverResult()
        {
            DangerousImports = new List<DangerousImport>();
            ExportedDangerousFunctions = new List<string>();
            Devices = new List<DeviceInfo>();
            IoctlCodes = new List<IoctlInfo>();
            SuspiciousStrings = new List<string>();
            Sections = new List<SectionAnalysis>();
            SignerName = "";
            RiskReason = "";
            Impact = "";
            ExploitUse = "";
            Note = "";
            SourceLocation = "";
            Framework = DriverFramework.Unknown;
        }
    }

    public class DangerousImport
    {
        public string FunctionName { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
        public Reachability Reachability { get; set; }
        public TaintStatus Taint { get; set; }
        public BehaviorTag BehaviorTag { get; set; }

        public DangerousImport()
        {
            Reachability = Reachability.Unknown;
            Taint = TaintStatus.Unknown;
        }
    }

    public class DeviceInfo
    {
        public string DeviceName { get; set; }
        public string SymbolicLink { get; set; }
        public bool HasSecureOpen { get; set; }
        public string SddlAccess { get; set; }

        public DeviceInfo() { SddlAccess = ""; }
    }

    public class IoctlInfo
    {
        public uint Code { get; set; }
        public string CodeHex { get; set; }
        public int DeviceType { get; set; }
        public int Function { get; set; }
        public int Method { get; set; }
        public int Access { get; set; }
        public string MethodName { get; set; }
        public string AccessName { get; set; }
        public string FamilyMatch { get; set; }

        public IoctlInfo()
        {
            FamilyMatch = "";
            MethodName = "";
            AccessName = "";
        }

        public static IoctlInfo Decode(uint code)
        {
            var info = new IoctlInfo
            {
                Code = code,
                CodeHex = $"0x{code:X8}",
                DeviceType = (int)((code >> 16) & 0xFFFF),
                Function = (int)((code >> 2) & 0xFFF),
                Method = (int)(code & 0x3),
                Access = (int)((code >> 14) & 0x3)
            };
            switch (info.Method)
            {
                case 0: info.MethodName = "BUFFERED"; break;
                case 1: info.MethodName = "IN_DIRECT"; break;
                case 2: info.MethodName = "OUT_DIRECT"; break;
                case 3: info.MethodName = "NEITHER"; break;
            }
            switch (info.Access)
            {
                case 0: info.AccessName = "ANY_ACCESS"; break;
                case 1: info.AccessName = "READ_ACCESS"; break;
                case 2: info.AccessName = "WRITE_ACCESS"; break;
                case 3: info.AccessName = "READ_WRITE"; break;
            }
            return info;
        }
    }

    public class LolMatch
    {
        public string Id { get; set; }
        public string Category { get; set; }
        public List<string> CVEs { get; set; }
        public List<string> Tags { get; set; }
        public string KnownFileName { get; set; }

        public LolMatch()
        {
            CVEs = new List<string>();
            Tags = new List<string>();
            KnownFileName = "";
        }
    }

    public class MsBlocklistMatch
    {
        public string DriverName { get; set; }
        public string Description { get; set; }
        public bool HvciEnabled { get; set; }
        public bool BlocklistEnabled { get; set; }
    }

    public class IoctlFamilyMatch
    {
        public string FamilyName { get; set; }
        public string Description { get; set; }
        public string MatchedCode { get; set; }
    }

    public class VendorMatch
    {
        public string VendorName { get; set; }
        public string Reason { get; set; }
    }

    public class CertificateFlag
    {
        public string Reason { get; set; }
        public bool IsCompromised { get; set; }
        public bool IsTestSigned { get; set; }
        public bool IsSelfSigned { get; set; }
        public bool IsExpired { get; set; }
    }

    public class PeMetadata
    {
        public uint TimeDateStamp { get; set; }
        public string CompileDate { get; set; }
        public int AgeYears { get; set; }
        public string LinkerVersion { get; set; }
        public string PdbPath { get; set; }
        public bool IsPe32Plus { get; set; }
        public uint EntryPointRva { get; set; }

        public PeMetadata() { PdbPath = ""; LinkerVersion = ""; CompileDate = ""; }
    }

    public class PeMitigations
    {
        public bool HasASLR { get; set; }
        public bool HasDEP { get; set; }
        public bool HasCFG { get; set; }
        public bool HasForceIntegrity { get; set; }
        public int MissingCount { get; set; }
    }

    public class SectionAnalysis
    {
        public string Name { get; set; }
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
        public uint RawOffset { get; set; }
        public uint Characteristics { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsWritable { get; set; }
        public bool IsRWX { get; set; }
        public bool IsUnusualName { get; set; }
        public double Entropy { get; set; }
        public bool IsHighEntropy { get; set; }
    }

    public class VersionInfoData
    {
        public string CompanyName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string FileVersion { get; set; }
        public string OriginalFilename { get; set; }
        public string Copyright { get; set; }
        public bool FilenameMismatch { get; set; }
        public bool HasSuspiciousKeywords { get; set; }

        public VersionInfoData()
        {
            CompanyName = ""; FileDescription = ""; ProductName = "";
            FileVersion = ""; OriginalFilename = ""; Copyright = "";
        }
    }

    public class DispatchAnalysisResult
    {
        public Dictionary<int, uint> HandlerRvas { get; set; }
        public uint DeviceControlHandlerRva { get; set; }
        public uint CreateHandlerRva { get; set; }
        public AccessCheckVerdict CreateAccessCheck { get; set; }
        public BufferValidation BufferValidation { get; set; }
        public bool AllSameHandler { get; set; }
        public bool HasPreviousModeCheck { get; set; }
        public List<uint> ExtractedIoctlCodes { get; set; }

        public DispatchAnalysisResult()
        {
            HandlerRvas = new Dictionary<int, uint>();
            ExtractedIoctlCodes = new List<uint>();
            CreateAccessCheck = AccessCheckVerdict.Unknown;
            BufferValidation = BufferValidation.Unknown;
        }
    }

    public class SystemProtection
    {
        public string WindowsVersion { get; set; }
        public string BuildNumber { get; set; }
        public bool HvciEnabled { get; set; }
        public bool SecureBootEnabled { get; set; }
        public bool DseEnforced { get; set; }
        public bool TestSigningEnabled { get; set; }
        public bool VbsEnabled { get; set; }
        public bool WdacPolicyPresent { get; set; }
        public bool BlocklistEnabled { get; set; }

        public SystemProtection()
        {
            WindowsVersion = "Unknown";
            BuildNumber = "";
        }
    }

    public class ScanSummary
    {
        public int TotalScanned { get; set; }
        public int WhitelistedCount { get; set; }
        public int CurrentlyLoaded { get; set; }
        public int LolDriversMatches { get; set; }
        public int MsBlocklistMatches { get; set; }
        public int IoctlFamilyMatches { get; set; }
        public int CompromisedCertMatches { get; set; }
        public int KnownVulnVendorMatches { get; set; }
        public int IoctlReachableConfirmed { get; set; }
        public int TaintedParams { get; set; }
        public int UnreachableFpReduced { get; set; }
        public int CouldNotDetermine { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int MissingAslr { get; set; }
        public int MissingCfg { get; set; }
        public int RwxSections { get; set; }
        public int HighEntropySections { get; set; }
        public int Unsigned { get; set; }
        public int BehaviorB14Count { get; set; }
        public Dictionary<string, int> BehaviorCounts { get; set; }
        public SystemProtection SystemStatus { get; set; }
        public List<string> ScanPaths { get; set; }

        public ScanSummary()
        {
            ScanPaths = new List<string>();
            SystemStatus = new SystemProtection();
            BehaviorCounts = new Dictionary<string, int>();
        }
    }
}
