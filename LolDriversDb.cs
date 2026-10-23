using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web.Script.Serialization;

namespace BYOVDHunter
{
    public class LolDriversDb
    {
        private const string DriverJsonUrl = "https://www.loldrivers.io/api/drivers.json";

        private readonly Dictionary<string, LolMatch> _hashLookup =
            new Dictionary<string, LolMatch>(StringComparer.OrdinalIgnoreCase);

        public int Count => _hashLookup.Count;

        public static string GetCachePath()
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            return System.IO.Path.Combine(exeDir, "loldrivers_cache.json");
        }

        public bool Download(string cachePath)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11;
                using (var client = new WebClient())
                {
                    client.Headers.Add("User-Agent", "BYOVDHunter/1.0");
                    client.DownloadFile(DriverJsonUrl, cachePath);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  Failed to download LOLDrivers DB: {ex.Message}");
                return false;
            }
        }

        public bool Load(string cachePath)
        {
            try
            {
                string json = File.ReadAllText(cachePath);
                var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                var drivers = serializer.Deserialize<object[]>(json);

                if (drivers == null) return false;

                foreach (object driverObj in drivers)
                {
                    if (!(driverObj is Dictionary<string, object> driver))
                        continue;

                    string id = GetString(driver, "Id");
                    string category = GetString(driver, "Category");

                    var cves = new List<string>();
                    var tags = new List<string>();

                    if (driver.ContainsKey("Tags"))
                    {
                        foreach (object tag in AsEnumerable(driver["Tags"]))
                        {
                            string t = tag?.ToString() ?? "";
                            if (string.IsNullOrWhiteSpace(t)) continue;
                            if (t.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                                cves.Add(t);
                            else
                                tags.Add(t);
                        }
                    }

                    if (!driver.ContainsKey("KnownVulnerableSamples")) continue;

                    foreach (object sampleObj in AsEnumerable(driver["KnownVulnerableSamples"]))
                    {
                        if (!(sampleObj is Dictionary<string, object> sample))
                            continue;

                        string sha256 = GetString(sample, "SHA256");
                        if (string.IsNullOrWhiteSpace(sha256)) continue;

                        string filename = GetString(sample, "Filename");

                        var match = new LolMatch
                        {
                            Id = id,
                            Category = category,
                            CVEs = new List<string>(cves),
                            Tags = new List<string>(tags),
                            KnownFileName = filename
                        };

                        _hashLookup[sha256] = match;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  Failed to parse LOLDrivers DB: {ex.Message}");
                return false;
            }
        }

        public LolMatch Lookup(string sha256Hash)
        {
            if (string.IsNullOrWhiteSpace(sha256Hash)) return null;
            _hashLookup.TryGetValue(sha256Hash, out var match);
            return match;
        }

        private static string GetString(Dictionary<string, object> dict, string key)
        {
            if (dict.ContainsKey(key) && dict[key] != null)
                return dict[key].ToString();
            return "";
        }

        private static IEnumerable<object> AsEnumerable(object obj)
        {
            if (obj is ArrayList al) return al.Cast<object>();
            if (obj is object[] arr) return arr;
            return Enumerable.Empty<object>();
        }
    }
}
