using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace BYOVDHunter
{
    public static class PeParser
    {
        public static byte[] ReadFile(string filePath)
        {
            return File.ReadAllBytes(filePath);
        }

        public static bool IsValidPe(byte[] data)
        {
            if (data.Length < 64 || data[0] != 0x4D || data[1] != 0x5A) return false;
            int peOff = BitConverter.ToInt32(data, 0x3C);
            if (peOff < 0 || peOff + 4 > data.Length) return false;
            return data[peOff] == 0x50 && data[peOff + 1] == 0x45 && data[peOff + 2] == 0 && data[peOff + 3] == 0;
        }

        public struct PeHeaders
        {
            public int PeOffset;
            public int CoffOffset;
            public int OptionalOffset;
            public ushort NumberOfSections;
            public ushort SizeOfOptionalHeader;
            public bool IsPe32Plus;
            public uint EntryPointRva;
            public uint TimeDateStamp;
            public ushort MajorLinkerVersion;
            public ushort MinorLinkerVersion;
            public ushort DllCharacteristics;
            public int SectionHeadersStart;
            public int DataDirectoryOffset;
            public ulong ImageBase;
            public List<SectionEntry> Sections;
        }

        public struct SectionEntry
        {
            public string Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint Characteristics;
        }

        public static PeHeaders? ParseHeaders(byte[] data)
        {
            if (!IsValidPe(data)) return null;
            var h = new PeHeaders();
            h.PeOffset = BitConverter.ToInt32(data, 0x3C);
            h.CoffOffset = h.PeOffset + 4;
            if (h.CoffOffset + 20 > data.Length) return null;

            h.NumberOfSections = BitConverter.ToUInt16(data, h.CoffOffset + 2);
            h.TimeDateStamp = BitConverter.ToUInt32(data, h.CoffOffset + 4);
            h.SizeOfOptionalHeader = BitConverter.ToUInt16(data, h.CoffOffset + 16);
            h.OptionalOffset = h.CoffOffset + 20;

            if (h.OptionalOffset + 2 > data.Length) return null;
            ushort magic = BitConverter.ToUInt16(data, h.OptionalOffset);
            h.IsPe32Plus = magic == 0x20B;

            if (h.OptionalOffset + 28 > data.Length) return null;
            h.EntryPointRva = BitConverter.ToUInt32(data, h.OptionalOffset + 16);
            if (h.IsPe32Plus && h.OptionalOffset + 32 <= data.Length)
                h.ImageBase = BitConverter.ToUInt64(data, h.OptionalOffset + 24);
            else if (h.OptionalOffset + 32 <= data.Length)
                h.ImageBase = BitConverter.ToUInt32(data, h.OptionalOffset + 28);
            h.MajorLinkerVersion = data[h.OptionalOffset + 2];
            h.MinorLinkerVersion = data[h.OptionalOffset + 3];

            int dllCharOff = h.IsPe32Plus ? h.OptionalOffset + 70 : h.OptionalOffset + 66;
            if (dllCharOff + 2 <= data.Length)
                h.DllCharacteristics = BitConverter.ToUInt16(data, dllCharOff);

            h.DataDirectoryOffset = h.IsPe32Plus ? h.OptionalOffset + 112 : h.OptionalOffset + 96;
            h.SectionHeadersStart = h.OptionalOffset + h.SizeOfOptionalHeader;

            h.Sections = new List<SectionEntry>();
            for (int i = 0; i < h.NumberOfSections; i++)
            {
                int off = h.SectionHeadersStart + i * 40;
                if (off + 40 > data.Length) break;
                var sec = new SectionEntry();
                var nameBytes = new byte[8];
                Array.Copy(data, off, nameBytes, 0, 8);
                sec.Name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                sec.VirtualSize = BitConverter.ToUInt32(data, off + 8);
                sec.VirtualAddress = BitConverter.ToUInt32(data, off + 12);
                sec.SizeOfRawData = BitConverter.ToUInt32(data, off + 16);
                sec.PointerToRawData = BitConverter.ToUInt32(data, off + 20);
                sec.Characteristics = BitConverter.ToUInt32(data, off + 36);
                h.Sections.Add(sec);
            }
            return h;
        }

        public static int RvaToOffset(uint rva, List<SectionEntry> sections)
        {
            foreach (var s in sections)
            {
                uint extent = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + extent)
                    return (int)(rva - s.VirtualAddress + s.PointerToRawData);
            }
            return -1;
        }

        public static uint OffsetToRva(int offset, List<SectionEntry> sections)
        {
            foreach (var s in sections)
            {
                if (offset >= s.PointerToRawData && offset < s.PointerToRawData + s.SizeOfRawData)
                    return (uint)(offset - s.PointerToRawData + s.VirtualAddress);
            }
            return 0;
        }

        public static List<string> GetImportedFunctions(byte[] data)
        {
            var functions = new List<string>();
            try
            {
                var headers = ParseHeaders(data);
                if (headers == null) return functions;
                var h = headers.Value;

                int importDirEntry = h.DataDirectoryOffset + 8;
                if (importDirEntry + 8 > data.Length) return functions;
                uint importRva = BitConverter.ToUInt32(data, importDirEntry);
                if (importRva == 0) return functions;

                int importOff = RvaToOffset(importRva, h.Sections);
                if (importOff < 0) return functions;

                int desc = importOff;
                while (desc + 20 <= data.Length)
                {
                    uint oft = BitConverter.ToUInt32(data, desc);
                    uint nameRva = BitConverter.ToUInt32(data, desc + 12);
                    uint ft = BitConverter.ToUInt32(data, desc + 16);
                    if (oft == 0 && nameRva == 0 && ft == 0) break;

                    uint iltRva = oft != 0 ? oft : ft;
                    int iltOff = RvaToOffset(iltRva, h.Sections);
                    if (iltOff >= 0)
                    {
                        int entrySize = h.IsPe32Plus ? 8 : 4;
                        int pos = iltOff;
                        while (pos + entrySize <= data.Length)
                        {
                            ulong entry = h.IsPe32Plus
                                ? BitConverter.ToUInt64(data, pos)
                                : BitConverter.ToUInt32(data, pos);
                            if (entry == 0) break;
                            bool isOrdinal = h.IsPe32Plus
                                ? (entry & 0x8000000000000000UL) != 0
                                : (entry & 0x80000000UL) != 0;
                            if (!isOrdinal)
                            {
                                uint hintRva = (uint)(entry & 0x7FFFFFFFU);
                                int hintOff = RvaToOffset(hintRva, h.Sections);
                                if (hintOff >= 0 && hintOff + 2 < data.Length)
                                {
                                    string fn = ReadAsciiString(data, hintOff + 2);
                                    if (!string.IsNullOrEmpty(fn))
                                        functions.Add(fn);
                                }
                            }
                            pos += entrySize;
                        }
                    }
                    desc += 20;
                }
            }
            catch { }
            return functions;
        }

        public static Dictionary<uint, string> GetImportAddressTable(byte[] data)
        {
            var iat = new Dictionary<uint, string>();
            try
            {
                var headers = ParseHeaders(data);
                if (headers == null) return iat;
                var h = headers.Value;

                int importDirEntry = h.DataDirectoryOffset + 8;
                if (importDirEntry + 8 > data.Length) return iat;
                uint importRva = BitConverter.ToUInt32(data, importDirEntry);
                if (importRva == 0) return iat;

                int importOff = RvaToOffset(importRva, h.Sections);
                if (importOff < 0) return iat;

                int desc = importOff;
                while (desc + 20 <= data.Length)
                {
                    uint oft = BitConverter.ToUInt32(data, desc);
                    uint nameRva = BitConverter.ToUInt32(data, desc + 12);
                    uint ft = BitConverter.ToUInt32(data, desc + 16);
                    if (oft == 0 && nameRva == 0 && ft == 0) break;

                    uint iltRva = oft != 0 ? oft : ft;
                    uint iatRva = ft;
                    int iltOff = RvaToOffset(iltRva, h.Sections);
                    if (iltOff >= 0)
                    {
                        int entrySize = h.IsPe32Plus ? 8 : 4;
                        int pos = iltOff;
                        uint currentIatRva = iatRva;
                        while (pos + entrySize <= data.Length)
                        {
                            ulong entry = h.IsPe32Plus
                                ? BitConverter.ToUInt64(data, pos)
                                : BitConverter.ToUInt32(data, pos);
                            if (entry == 0) break;
                            bool isOrdinal = h.IsPe32Plus
                                ? (entry & 0x8000000000000000UL) != 0
                                : (entry & 0x80000000UL) != 0;
                            if (!isOrdinal)
                            {
                                uint hintRva = (uint)(entry & 0x7FFFFFFFU);
                                int hintOff = RvaToOffset(hintRva, h.Sections);
                                if (hintOff >= 0 && hintOff + 2 < data.Length)
                                {
                                    string fn = ReadAsciiString(data, hintOff + 2);
                                    if (!string.IsNullOrEmpty(fn))
                                        iat[currentIatRva] = fn;
                                }
                            }
                            pos += entrySize;
                            currentIatRva += (uint)entrySize;
                        }
                    }
                    desc += 20;
                }
            }
            catch { }
            return iat;
        }

        public static List<string> GetExportedFunctions(byte[] data)
        {
            var exports = new List<string>();
            try
            {
                var headers = ParseHeaders(data);
                if (headers == null) return exports;
                var h = headers.Value;

                int exportDirEntry = h.DataDirectoryOffset;
                if (exportDirEntry + 8 > data.Length) return exports;
                uint exportRva = BitConverter.ToUInt32(data, exportDirEntry);
                if (exportRva == 0) return exports;

                int exportOff = RvaToOffset(exportRva, h.Sections);
                if (exportOff < 0 || exportOff + 40 > data.Length) return exports;

                uint numberOfNames = BitConverter.ToUInt32(data, exportOff + 24);
                uint namePointerRva = BitConverter.ToUInt32(data, exportOff + 32);
                int namePointerOff = RvaToOffset(namePointerRva, h.Sections);
                if (namePointerOff < 0) return exports;

                for (uint i = 0; i < numberOfNames && i < 500; i++)
                {
                    int nOff = namePointerOff + (int)(i * 4);
                    if (nOff + 4 > data.Length) break;
                    uint fnNameRva = BitConverter.ToUInt32(data, nOff);
                    int fnNameOff = RvaToOffset(fnNameRva, h.Sections);
                    if (fnNameOff >= 0)
                    {
                        string name = ReadAsciiString(data, fnNameOff);
                        if (!string.IsNullOrEmpty(name))
                            exports.Add(name);
                    }
                }
            }
            catch { }
            return exports;
        }

        public static List<string> FindDeviceNames(byte[] data)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] prefixes = { "\\Device\\", "\\DosDevices\\", "\\??\\", "\\\\.\\" };
            foreach (string prefix in prefixes)
            {
                byte[] pattern = Encoding.Unicode.GetBytes(prefix);
                int pos = 0;
                while (pos < data.Length - pattern.Length)
                {
                    pos = IndexOfBytes(data, pattern, pos);
                    if (pos < 0) break;
                    string str = ReadUnicodeString(data, pos);
                    if (str.Length > prefix.Length + 1 && !IsGarbageString(str))
                        names.Add(str);
                    pos += 2;
                }
            }
            return names.Take(15).ToList();
        }

        public static List<uint> FindIoctlCodes(byte[] data)
        {
            var candidates = new List<KeyValuePair<int, uint>>();
            for (int i = 512; i <= data.Length - 4; i++)
            {
                uint val = BitConverter.ToUInt32(data, i);
                uint deviceType = (val >> 16) & 0xFFFF;
                uint function = (val >> 2) & 0xFFF;
                if (deviceType == 0x22 || (deviceType >= 0x8000 && deviceType <= 0x80FF))
                {
                    if (function >= 1 && function <= 0xFFF)
                        candidates.Add(new KeyValuePair<int, uint>(i, val));
                }
            }
            var result = new HashSet<uint>();
            for (int i = 0; i < candidates.Count; i++)
            {
                bool hasNeighbor = false;
                if (i > 0 && candidates[i].Key - candidates[i - 1].Key <= 256) hasNeighbor = true;
                if (i < candidates.Count - 1 && candidates[i + 1].Key - candidates[i].Key <= 256) hasNeighbor = true;
                if (hasNeighbor) result.Add(candidates[i].Value);
                if (result.Count >= 20) break;
            }
            return result.OrderBy(c => c).ToList();
        }

        public static List<string> FindSuspiciousStrings(byte[] data)
        {
            var found = new List<string>();
            string[] patterns =
            {
                "PhysicalMemory", "SeDebugPrivilege", "SeTcbPrivilege",
                "ZwWriteVirtualMemory", "ZwReadVirtualMemory",
                "NtWriteVirtualMemory", "NtReadVirtualMemory",
                "g_CiEnabled", "g_CiOptions", "ci.dll",
            };
            foreach (string pattern in patterns)
            {
                byte[] ascii = Encoding.ASCII.GetBytes(pattern);
                byte[] unicode = Encoding.Unicode.GetBytes(pattern);
                if (IndexOfBytes(data, ascii, 0) >= 0 || IndexOfBytes(data, unicode, 0) >= 0)
                    found.Add(pattern);
            }
            return found;
        }

        public static List<string> FindSddlStrings(byte[] data)
        {
            var found = new List<string>();
            byte[] sddlAscii = Encoding.ASCII.GetBytes("D:P(A;;");
            byte[] sddlAscii2 = Encoding.ASCII.GetBytes("D:(A;;");
            byte[] sddlUni = Encoding.Unicode.GetBytes("D:P(A;;");
            byte[] sddlUni2 = Encoding.Unicode.GetBytes("D:(A;;");

            foreach (var pat in new[] { sddlAscii, sddlAscii2 })
            {
                int pos = IndexOfBytes(data, pat, 0);
                if (pos >= 0)
                {
                    string s = ReadAsciiString(data, pos);
                    if (s.Length > 6) found.Add(s);
                }
            }
            foreach (var pat in new[] { sddlUni, sddlUni2 })
            {
                int pos = IndexOfBytes(data, pat, 0);
                if (pos >= 0)
                {
                    string s = ReadUnicodeString(data, pos);
                    if (s.Length > 6) found.Add(s);
                }
            }
            return found;
        }

        public static string GetPdbPath(byte[] data)
        {
            try
            {
                var headers = ParseHeaders(data);
                if (headers == null) return null;
                var h = headers.Value;

                int debugDirEntry = h.DataDirectoryOffset + 6 * 8;
                if (debugDirEntry + 8 > data.Length) return null;
                uint debugRva = BitConverter.ToUInt32(data, debugDirEntry);
                uint debugSize = BitConverter.ToUInt32(data, debugDirEntry + 4);
                if (debugRva == 0 || debugSize == 0) return null;

                int debugOff = RvaToOffset(debugRva, h.Sections);
                if (debugOff < 0) return null;

                int count = (int)(debugSize / 28);
                for (int i = 0; i < count; i++)
                {
                    int entryOff = debugOff + i * 28;
                    if (entryOff + 28 > data.Length) break;
                    uint type = BitConverter.ToUInt32(data, entryOff + 12);
                    if (type == 2) // IMAGE_DEBUG_TYPE_CODEVIEW
                    {
                        uint dataOffset = BitConverter.ToUInt32(data, entryOff + 24);
                        if (dataOffset + 24 > data.Length) continue;
                        if (data[dataOffset] == 'R' && data[dataOffset + 1] == 'S' &&
                            data[dataOffset + 2] == 'D' && data[dataOffset + 3] == 'S')
                        {
                            int pdbOff = (int)dataOffset + 24;
                            return ReadAsciiString(data, pdbOff);
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        #region Helpers

        public static int IndexOfBytes(byte[] data, byte[] pattern, int start)
        {
            if (pattern.Length == 0 || data.Length < pattern.Length) return -1;
            int end = data.Length - pattern.Length;
            byte first = pattern[0];
            for (int i = start; i <= end; i++)
            {
                if (data[i] != first) continue;
                bool match = true;
                for (int j = 1; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        public static string ReadUnicodeString(byte[] data, int offset)
        {
            var sb = new StringBuilder();
            int pos = offset;
            while (pos + 1 < data.Length && sb.Length < 256)
            {
                ushort ch = BitConverter.ToUInt16(data, pos);
                if (ch == 0 || ch < 0x20 || ch > 0x7E) break;
                sb.Append((char)ch);
                pos += 2;
            }
            return sb.ToString();
        }

        public static string ReadAsciiString(byte[] data, int offset)
        {
            var sb = new StringBuilder();
            while (offset < data.Length && data[offset] != 0 && sb.Length < 512)
            {
                char c = (char)data[offset];
                if (c < 0x20 || c > 0x7E) break;
                sb.Append(c);
                offset++;
            }
            return sb.ToString();
        }

        private static bool IsGarbageString(string s)
        {
            if (s.Length < 4) return true;
            int alphaCount = s.Count(c => char.IsLetterOrDigit(c));
            return alphaCount < s.Length / 3;
        }

        #endregion
    }
}
