using System;
using System.IO;
using Microsoft.Win32;

namespace BYOVDHunter
{
    public static class SystemStatus
    {
        public static SystemProtection Check()
        {
            var status = new SystemProtection();

            try
            {
                var os = Environment.OSVersion;
                string product = ReadReg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName") as string ?? "Windows";
                string displayVersion = ReadReg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion") as string ?? "";
                string build = ReadReg(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") as string ?? os.Version.Build.ToString();
                status.WindowsVersion = $"{product} {displayVersion}".Trim();
                status.BuildNumber = build;
            }
            catch { }

            try
            {
                object hvci = ReadReg(
                    @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                    "Enabled");
                status.HvciEnabled = hvci != null && Convert.ToInt32(hvci) != 0;
            }
            catch { }

            try
            {
                object sb = ReadReg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
                status.SecureBootEnabled = sb != null && Convert.ToInt32(sb) != 0;
            }
            catch { }

            try
            {
                object testSign = ReadReg(@"SYSTEM\CurrentControlSet\Control\CI", "TestSigning");
                status.TestSigningEnabled = testSign != null && Convert.ToInt32(testSign) != 0;
                status.DseEnforced = !status.TestSigningEnabled;
            }
            catch
            {
                status.DseEnforced = true;
            }

            try
            {
                object vbs = ReadReg(@"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity");
                status.VbsEnabled = vbs != null && Convert.ToInt32(vbs) != 0;
            }
            catch { }

            try
            {
                string policyPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "CodeIntegrity", "SIPolicy.p7b");
                status.WdacPolicyPresent = File.Exists(policyPath);
            }
            catch { }

            try
            {
                object bl = ReadReg(@"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");
                status.BlocklistEnabled = bl != null && Convert.ToInt32(bl) != 0;
            }
            catch { }

            return status;
        }

        private static object ReadReg(string subkey, string valueName)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(subkey))
                {
                    return key?.GetValue(valueName);
                }
            }
            catch { return null; }
        }
    }
}
