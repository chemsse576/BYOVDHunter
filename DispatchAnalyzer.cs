using System;
using System.Collections.Generic;
using System.Linq;

namespace BYOVDHunter
{
    public static class DispatchAnalyzer
    {
        private static readonly int[] MajorFunctionOffsets64 =
        {
            0x70,  // IRP_MJ_CREATE (0)
            0x78,  // IRP_MJ_CREATE_NAMED_PIPE (1)
            0x80,  // IRP_MJ_CLOSE (2)
            0x88,  // IRP_MJ_READ (3)
            0x90,  // IRP_MJ_WRITE (4)
            0xE0,  // IRP_MJ_DEVICE_CONTROL (14)
            0xE8,  // IRP_MJ_INTERNAL_DEVICE_CONTROL (15)
        };

        private static readonly int[] MajorFunctionOffsets32 =
        {
            0x38,  // IRP_MJ_CREATE (0)
            0x3C,  // IRP_MJ_CREATE_NAMED_PIPE (1)
            0x40,  // IRP_MJ_CLOSE (2)
            0x44,  // IRP_MJ_READ (3)
            0x48,  // IRP_MJ_WRITE (4)
            0x70,  // IRP_MJ_DEVICE_CONTROL (14)
            0x74,  // IRP_MJ_INTERNAL_DEVICE_CONTROL (15)
        };

        private static readonly int[] MajorFunctionIndices = { 0, 1, 2, 3, 4, 14, 15 };

        public static DispatchAnalysisResult Analyze(byte[] data, PeParser.PeHeaders headers,
            Dictionary<uint, string> iatMap, HashSet<string> dangerousImportNames)
        {
            var result = new DispatchAnalysisResult();
            try
            {
                int entryOffset = PeParser.RvaToOffset(headers.EntryPointRva, headers.Sections);
                if (entryOffset < 0 || entryOffset >= data.Length) return result;

                if (headers.IsPe32Plus)
                    ExtractDispatchTable64(data, entryOffset, headers, result);
                else
                    ExtractDispatchTable32(data, entryOffset, headers, result);

                if (result.DeviceControlHandlerRva != 0)
                {
                    int handlerOff = PeParser.RvaToOffset(result.DeviceControlHandlerRva, headers.Sections);
                    if (handlerOff > 0 && handlerOff < data.Length)
                    {
                        result.ExtractedIoctlCodes = ExtractIoctlCodesFromHandler(data, handlerOff, headers);
                        result.BufferValidation = CheckBufferValidation(data, handlerOff, headers, iatMap);
                        result.HasPreviousModeCheck = CheckPreviousModeCheck(data, handlerOff, headers, iatMap);
                    }
                }

                if (result.CreateHandlerRva != 0)
                {
                    int createOff = PeParser.RvaToOffset(result.CreateHandlerRva, headers.Sections);
                    if (createOff > 0 && createOff < data.Length)
                        result.CreateAccessCheck = AnalyzeCreateHandler(data, createOff, headers, iatMap);
                }

                if (result.HandlerRvas.Count >= 2)
                {
                    var distinctHandlers = new HashSet<uint>(result.HandlerRvas.Values);
                    result.AllSameHandler = distinctHandlers.Count == 1;
                }
            }
            catch { }
            return result;
        }

        public static Dictionary<string, Reachability> AnalyzeReachability(byte[] data,
            PeParser.PeHeaders headers, uint handlerRva,
            Dictionary<uint, string> iatMap, HashSet<string> dangerousNames)
        {
            var reachability = new Dictionary<string, Reachability>();
            foreach (var name in dangerousNames)
                reachability[name] = Reachability.Unknown;

            try
            {
                int handlerOff = PeParser.RvaToOffset(handlerRva, headers.Sections);
                if (handlerOff < 0) return reachability;

                var level0Calls = FindCallTargets(data, handlerOff, 4096, headers);

                foreach (var call in level0Calls)
                {
                    if (call.IsIatCall && iatMap.ContainsKey(call.TargetRva))
                    {
                        string name = iatMap[call.TargetRva];
                        if (dangerousNames.Contains(name))
                            reachability[name] = Reachability.Direct;
                    }
                }

                foreach (var call in level0Calls)
                {
                    if (call.IsIatCall) continue;
                    int targetOff = PeParser.RvaToOffset(call.TargetRva, headers.Sections);
                    if (targetOff < 0 || targetOff >= data.Length) continue;

                    var level1Calls = FindCallTargets(data, targetOff, 2048, headers);
                    foreach (var sub in level1Calls)
                    {
                        if (sub.IsIatCall && iatMap.ContainsKey(sub.TargetRva))
                        {
                            string name = iatMap[sub.TargetRva];
                            if (dangerousNames.Contains(name) && reachability[name] != Reachability.Direct)
                                reachability[name] = Reachability.Indirect;
                        }
                    }

                    foreach (var sub in level1Calls)
                    {
                        if (sub.IsIatCall) continue;
                        int subOff = PeParser.RvaToOffset(sub.TargetRva, headers.Sections);
                        if (subOff < 0 || subOff >= data.Length) continue;

                        var level2Calls = FindCallTargets(data, subOff, 1024, headers);
                        foreach (var subsub in level2Calls)
                        {
                            if (subsub.IsIatCall && iatMap.ContainsKey(subsub.TargetRva))
                            {
                                string name = iatMap[subsub.TargetRva];
                                if (dangerousNames.Contains(name) &&
                                    reachability[name] != Reachability.Direct &&
                                    reachability[name] != Reachability.Indirect)
                                    reachability[name] = Reachability.Indirect;
                            }
                        }
                    }
                }

                foreach (var key in reachability.Keys.ToList())
                {
                    if (reachability[key] == Reachability.Unknown)
                    {
                        bool inIat = iatMap.Values.Contains(key);
                        if (inIat) reachability[key] = Reachability.NotReachable;
                    }
                }
            }
            catch { }
            return reachability;
        }

        public static TaintStatus AnalyzeTaint(byte[] data, int callSiteFileOffset,
            PeParser.PeHeaders headers)
        {
            try
            {
                int searchStart = Math.Max(0, callSiteFileOffset - 48);
                int searchEnd = callSiteFileOffset;

                for (int i = searchEnd - 7; i >= searchStart; i--)
                {
                    if (i + 7 > data.Length) continue;

                    // MOV RCX, imm64 (48 B9 XX..): constant -> NOT_TAINTED
                    if (data[i] == 0x48 && data[i + 1] == 0xB9)
                        return TaintStatus.NotTainted;

                    // MOV ECX, imm32 (B9 XX XX XX XX): constant -> NOT_TAINTED
                    if (data[i] == 0xB9 && i + 5 <= data.Length)
                    {
                        uint val = BitConverter.ToUInt32(data, i + 1);
                        if (val > 0x10000) return TaintStatus.NotTainted;
                    }

                    // LEA RCX, [RIP+disp32] (48 8D 0D XX XX XX XX): -> NOT_TAINTED
                    if (data[i] == 0x48 && data[i + 1] == 0x8D && data[i + 2] == 0x0D)
                        return TaintStatus.NotTainted;

                    // MOV RCX, [reg+disp8/32] patterns where reg could be buffer pointer
                    // 48 8B 4B XX or 48 8B 4D XX = MOV RCX, [RBX+disp8] / [RBP+disp8]
                    if (data[i] == 0x48 && data[i + 1] == 0x8B)
                    {
                        byte modrm = data[i + 2];
                        int reg = (modrm >> 3) & 7;
                        int mod = (modrm >> 6) & 3;
                        if (reg == 1 && (mod == 1 || mod == 2)) // dst=RCX, indirect addressing
                            return TaintStatus.LikelyTainted;
                    }

                    // MOV RCX, [RSP+disp] = loading from stack (common for input buffer)
                    // 48 8B 8C 24 XX XX XX XX (with SIB byte for RSP base)
                    if (i + 8 <= data.Length && data[i] == 0x48 && data[i + 1] == 0x8B &&
                        data[i + 2] == 0x8C && data[i + 3] == 0x24)
                        return TaintStatus.LikelyTainted;
                }
            }
            catch { }
            return TaintStatus.Unknown;
        }

        #region Private helpers

        private static void ExtractDispatchTable64(byte[] data, int entryOffset,
            PeParser.PeHeaders headers, DispatchAnalysisResult result)
        {
            ScanDispatchPatterns64(data, entryOffset, headers, result);

            if (result.HandlerRvas.Count == 0)
            {
                var callTargets = new List<int>();
                int callScanEnd = Math.Min(entryOffset + 8192, data.Length - 5);
                for (int i = entryOffset; i < callScanEnd && callTargets.Count < 4; i++)
                {
                    if (data[i] == 0xE8 && i + 5 <= data.Length)
                    {
                        int disp = BitConverter.ToInt32(data, i + 1);
                        uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                        if (instrRva > 0)
                        {
                            uint targetRva = (uint)(instrRva + 5 + disp);
                            int targetOff = PeParser.RvaToOffset(targetRva, headers.Sections);
                            if (targetOff > 0 && targetOff < data.Length)
                                callTargets.Add(targetOff);
                        }
                        i += 4;
                        continue;
                    }
                    if (data[i] == 0xC3) break;
                }

                foreach (int targetOff in callTargets)
                {
                    ScanDispatchPatterns64(data, targetOff, headers, result);
                    if (result.HandlerRvas.Count > 0) break;
                }
            }
        }

        private static void ScanDispatchPatterns64(byte[] data, int startOffset,
            PeParser.PeHeaders headers, DispatchAnalysisResult result)
        {
            var regLeaTarget = new Dictionary<int, uint>();
            int scanEnd = Math.Min(startOffset + 8192, data.Length - 7);

            for (int i = startOffset; i < scanEnd; i++)
            {
                if (i + 7 <= data.Length && (data[i] == 0x48 || data[i] == 0x4C) && data[i + 1] == 0x8D)
                {
                    byte modrm = data[i + 2];
                    int mod = (modrm >> 6) & 3;
                    int rm = modrm & 7;
                    int regField = (modrm >> 3) & 7;

                    if (mod == 0 && rm == 5)
                    {
                        int disp = BitConverter.ToInt32(data, i + 3);
                        uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                        if (instrRva > 0)
                        {
                            uint targetRva = (uint)(instrRva + 7 + disp);
                            int regIndex = regField + (data[i] == 0x4C ? 8 : 0);
                            regLeaTarget[regIndex] = targetRva;
                        }
                        i += 6;
                        continue;
                    }
                }

                if (i + 7 <= data.Length &&
                    (data[i] == 0x48 || data[i] == 0x49 || data[i] == 0x4C) &&
                    data[i + 1] == 0x89)
                {
                    byte modrm = data[i + 2];
                    int mod = (modrm >> 6) & 3;
                    int rm = modrm & 7;
                    int regField = (modrm >> 3) & 7;

                    if (mod == 2 && rm != 4)
                    {
                        int disp32 = BitConverter.ToInt32(data, i + 3);

                        for (int j = 0; j < MajorFunctionOffsets64.Length; j++)
                        {
                            if (disp32 == MajorFunctionOffsets64[j])
                            {
                                int srcReg = regField + (data[i] == 0x4C ? 8 : 0);
                                if (regLeaTarget.ContainsKey(srcReg))
                                {
                                    int mjIndex = MajorFunctionIndices[j];
                                    result.HandlerRvas[mjIndex] = regLeaTarget[srcReg];

                                    if (mjIndex == 14)
                                        result.DeviceControlHandlerRva = regLeaTarget[srcReg];
                                    else if (mjIndex == 0)
                                        result.CreateHandlerRva = regLeaTarget[srcReg];
                                }
                                break;
                            }
                        }
                        i += 6;
                        continue;
                    }
                }

                if (data[i] == 0xC3 && result.HandlerRvas.Count > 0)
                    break;
            }
        }

        private static void ExtractDispatchTable32(byte[] data, int entryOffset,
            PeParser.PeHeaders headers, DispatchAnalysisResult result)
        {
            ScanDispatchPatterns32(data, entryOffset, headers, result);

            if (result.HandlerRvas.Count == 0)
            {
                var callTargets = new List<int>();
                int callScanEnd = Math.Min(entryOffset + 8192, data.Length - 5);
                for (int i = entryOffset; i < callScanEnd && callTargets.Count < 4; i++)
                {
                    if (data[i] == 0xE8 && i + 5 <= data.Length)
                    {
                        int disp = BitConverter.ToInt32(data, i + 1);
                        uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                        if (instrRva > 0)
                        {
                            uint targetRva = (uint)(instrRva + 5 + disp);
                            int targetOff = PeParser.RvaToOffset(targetRva, headers.Sections);
                            if (targetOff > 0 && targetOff < data.Length)
                                callTargets.Add(targetOff);
                        }
                        i += 4;
                        continue;
                    }
                    if (data[i] == 0xC3) break;
                }

                foreach (int targetOff in callTargets)
                {
                    ScanDispatchPatterns32(data, targetOff, headers, result);
                    if (result.HandlerRvas.Count > 0) break;
                }
            }
        }

        private static void ScanDispatchPatterns32(byte[] data, int startOffset,
            PeParser.PeHeaders headers, DispatchAnalysisResult result)
        {
            var regValues = new Dictionary<int, uint>();
            ulong imageBase = headers.ImageBase;
            int scanEnd = Math.Min(startOffset + 8192, data.Length - 6);

            for (int i = startOffset; i < scanEnd; i++)
            {
                // MOV reg, imm32: B8+rd imm32
                if (data[i] >= 0xB8 && data[i] <= 0xBF && i + 5 <= data.Length)
                {
                    int reg = data[i] - 0xB8;
                    uint imm = BitConverter.ToUInt32(data, i + 1);
                    if (imm > imageBase && imm < imageBase + 0x10000000)
                        regValues[reg] = imm;
                    i += 4;
                    continue;
                }

                // LEA reg, [disp32]: 8D ModRM disp32 (mod=0, rm=5)
                if (data[i] == 0x8D && i + 6 <= data.Length)
                {
                    byte modrm = data[i + 1];
                    int mod = (modrm >> 6) & 3;
                    int rm = modrm & 7;
                    int reg = (modrm >> 3) & 7;
                    if (mod == 0 && rm == 5)
                    {
                        uint addr = BitConverter.ToUInt32(data, i + 2);
                        if (addr > imageBase && addr < imageBase + 0x10000000)
                            regValues[reg] = addr;
                        i += 5;
                        continue;
                    }
                }

                // MOV [reg+disp8], imm32: C7 ModRM disp8 imm32
                // MOV [reg+disp32], imm32: C7 ModRM disp32 imm32
                if (data[i] == 0xC7)
                {
                    byte modrm = data[i + 1];
                    int mod = (modrm >> 6) & 3;
                    int rm = modrm & 7;
                    int regOp = (modrm >> 3) & 7;

                    if (regOp == 0 && mod == 1 && rm != 4 && i + 7 <= data.Length)
                    {
                        int disp = (sbyte)data[i + 2];
                        uint imm = BitConverter.ToUInt32(data, i + 3);

                        for (int j = 0; j < MajorFunctionOffsets32.Length; j++)
                        {
                            if (disp == MajorFunctionOffsets32[j] && imm > imageBase)
                            {
                                uint handlerRva = (uint)(imm - imageBase);
                                if (handlerRva < 0x10000000)
                                {
                                    int mjIndex = MajorFunctionIndices[j];
                                    result.HandlerRvas[mjIndex] = handlerRva;
                                    if (mjIndex == 14) result.DeviceControlHandlerRva = handlerRva;
                                    else if (mjIndex == 0) result.CreateHandlerRva = handlerRva;
                                }
                                break;
                            }
                        }
                        i += 6;
                        continue;
                    }

                    if (regOp == 0 && mod == 2 && rm != 4 && i + 10 <= data.Length)
                    {
                        int disp = BitConverter.ToInt32(data, i + 2);
                        uint imm = BitConverter.ToUInt32(data, i + 6);

                        for (int j = 0; j < MajorFunctionOffsets32.Length; j++)
                        {
                            if (disp == MajorFunctionOffsets32[j] && imm > imageBase)
                            {
                                uint handlerRva = (uint)(imm - imageBase);
                                if (handlerRva < 0x10000000)
                                {
                                    int mjIndex = MajorFunctionIndices[j];
                                    result.HandlerRvas[mjIndex] = handlerRva;
                                    if (mjIndex == 14) result.DeviceControlHandlerRva = handlerRva;
                                    else if (mjIndex == 0) result.CreateHandlerRva = handlerRva;
                                }
                                break;
                            }
                        }
                        i += 9;
                        continue;
                    }
                }

                // MOV [reg+disp], src_reg: 89 ModRM disp8/disp32
                if (data[i] == 0x89 && i + 3 <= data.Length)
                {
                    byte modrm = data[i + 1];
                    int mod = (modrm >> 6) & 3;
                    int rm = modrm & 7;
                    int srcReg = (modrm >> 3) & 7;

                    int disp = 0;
                    int instrLen = 0;

                    if (mod == 1 && rm != 4)
                    {
                        disp = (sbyte)data[i + 2];
                        instrLen = 3;
                    }
                    else if (mod == 2 && rm != 4 && i + 6 <= data.Length)
                    {
                        disp = BitConverter.ToInt32(data, i + 2);
                        instrLen = 6;
                    }

                    if (instrLen > 0 && regValues.ContainsKey(srcReg))
                    {
                        for (int j = 0; j < MajorFunctionOffsets32.Length; j++)
                        {
                            if (disp == MajorFunctionOffsets32[j])
                            {
                                uint va = regValues[srcReg];
                                uint handlerRva = (uint)(va - imageBase);
                                if (handlerRva > 0 && handlerRva < 0x10000000)
                                {
                                    int mjIndex = MajorFunctionIndices[j];
                                    result.HandlerRvas[mjIndex] = handlerRva;
                                    if (mjIndex == 14) result.DeviceControlHandlerRva = handlerRva;
                                    else if (mjIndex == 0) result.CreateHandlerRva = handlerRva;
                                }
                                break;
                            }
                        }
                        i += instrLen - 1;
                        continue;
                    }
                }

                if (data[i] == 0xC3 && result.HandlerRvas.Count > 0)
                    break;
            }
        }

        private static List<uint> ExtractIoctlCodesFromHandler(byte[] data, int handlerOffset,
            PeParser.PeHeaders headers)
        {
            var codes = new HashSet<uint>();
            int scanEnd = Math.Min(handlerOffset + 4096, data.Length - 6);

            for (int i = handlerOffset; i < scanEnd; i++)
            {
                uint imm32 = 0;
                bool found = false;

                // CMP EAX, imm32: 3D XX XX XX XX
                if (data[i] == 0x3D && i + 5 <= data.Length)
                {
                    imm32 = BitConverter.ToUInt32(data, i + 1);
                    found = true;
                }
                // CMP r32, imm32: 81 F8-FF XX XX XX XX
                else if (data[i] == 0x81 && i + 6 <= data.Length)
                {
                    byte modrm = data[i + 1];
                    int regOp = (modrm >> 3) & 7;
                    int mod = (modrm >> 6) & 3;
                    if (mod == 3 && regOp == 7) // CMP r32, imm32
                    {
                        imm32 = BitConverter.ToUInt32(data, i + 2);
                        found = true;
                    }
                }
                // SUB EAX, imm32: 2D XX XX XX XX
                else if (data[i] == 0x2D && i + 5 <= data.Length)
                {
                    imm32 = BitConverter.ToUInt32(data, i + 1);
                    found = true;
                }
                // With REX.B prefix: 41 81 F8-FF XX XX XX XX
                else if (data[i] == 0x41 && i + 7 <= data.Length && data[i + 1] == 0x81)
                {
                    byte modrm = data[i + 2];
                    int regOp = (modrm >> 3) & 7;
                    int mod = (modrm >> 6) & 3;
                    if (mod == 3 && regOp == 7)
                    {
                        imm32 = BitConverter.ToUInt32(data, i + 3);
                        found = true;
                    }
                }

                if (found && IsValidIoctlCode(imm32))
                    codes.Add(imm32);

                if (codes.Count >= 30) break;
            }
            return codes.OrderBy(c => c).ToList();
        }

        private struct CallTarget
        {
            public uint TargetRva;
            public bool IsIatCall;
            public int FileOffset;
        }

        private static List<CallTarget> FindCallTargets(byte[] data, int funcOffset, int maxScan,
            PeParser.PeHeaders headers)
        {
            var targets = new List<CallTarget>();
            int scanEnd = Math.Min(funcOffset + maxScan, data.Length - 6);
            int retCount = 0;

            for (int i = funcOffset; i < scanEnd; i++)
            {
                // CALL rel32: E8 XX XX XX XX
                if (data[i] == 0xE8 && i + 5 <= data.Length)
                {
                    int disp = BitConverter.ToInt32(data, i + 1);
                    uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                    if (instrRva > 0)
                    {
                        uint targetRva = (uint)(instrRva + 5 + disp);
                        if (targetRva > 0x1000 && targetRva < 0x10000000)
                        {
                            targets.Add(new CallTarget
                            {
                                TargetRva = targetRva,
                                IsIatCall = false,
                                FileOffset = PeParser.RvaToOffset(targetRva, headers.Sections)
                            });
                        }
                    }
                    i += 4;
                    continue;
                }

                // CALL [RIP+disp32]: FF 15 XX XX XX XX
                if (data[i] == 0xFF && i + 6 <= data.Length && data[i + 1] == 0x15)
                {
                    int disp = BitConverter.ToInt32(data, i + 2);
                    uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                    if (instrRva > 0)
                    {
                        uint iatRva = (uint)(instrRva + 6 + disp);
                        targets.Add(new CallTarget
                        {
                            TargetRva = iatRva,
                            IsIatCall = true,
                            FileOffset = -1
                        });
                    }
                    i += 5;
                    continue;
                }

                // JMP [RIP+disp32]: FF 25 XX XX XX XX (tail call through IAT)
                if (data[i] == 0xFF && i + 6 <= data.Length && data[i + 1] == 0x25)
                {
                    int disp = BitConverter.ToInt32(data, i + 2);
                    uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                    if (instrRva > 0)
                    {
                        uint iatRva = (uint)(instrRva + 6 + disp);
                        targets.Add(new CallTarget
                        {
                            TargetRva = iatRva,
                            IsIatCall = true,
                            FileOffset = -1
                        });
                    }
                    i += 5;
                    continue;
                }

                // JMP rel32: E9 XX XX XX XX (tail call to local func)
                if (data[i] == 0xE9 && i + 5 <= data.Length)
                {
                    int disp = BitConverter.ToInt32(data, i + 1);
                    uint instrRva = PeParser.OffsetToRva(i, headers.Sections);
                    if (instrRva > 0)
                    {
                        uint targetRva = (uint)(instrRva + 5 + disp);
                        if (targetRva > 0x1000 && targetRva < 0x10000000)
                        {
                            targets.Add(new CallTarget
                            {
                                TargetRva = targetRva,
                                IsIatCall = false,
                                FileOffset = PeParser.RvaToOffset(targetRva, headers.Sections)
                            });
                        }
                    }
                    break; // JMP is typically end of function/block
                }

                // RET: C3 - count returns, stop after second one
                if (data[i] == 0xC3)
                {
                    retCount++;
                    if (retCount >= 3) break;
                }
            }
            return targets;
        }

        private static AccessCheckVerdict AnalyzeCreateHandler(byte[] data, int handlerOffset,
            PeParser.PeHeaders headers, Dictionary<uint, string> iatMap)
        {
            var calls = FindCallTargets(data, handlerOffset, 1024, headers);

            string[] accessCheckFuncs =
            {
                "SeAccessCheck", "SeSinglePrivilegeCheck", "IoCheckShareAccess",
                "SeLockSubjectContext", "SePrivilegeCheck", "ObReferenceObjectByHandle",
                "ExGetPreviousMode", "KeGetPreviousMode", "PsGetCurrentProcessId",
                "IoGetCurrentProcess"
            };

            foreach (var call in calls)
            {
                if (call.IsIatCall && iatMap.ContainsKey(call.TargetRva))
                {
                    string name = iatMap[call.TargetRva];
                    if (accessCheckFuncs.Any(f => f.Equals(name, StringComparison.OrdinalIgnoreCase)))
                        return AccessCheckVerdict.HasChecks;
                }
            }

            // Check if handler is trivially short (just STATUS_SUCCESS + IoCompleteRequest + return)
            int bytesToRet = 0;
            for (int i = handlerOffset; i < Math.Min(handlerOffset + 128, data.Length); i++)
            {
                if (data[i] == 0xC3) { bytesToRet = i - handlerOffset; break; }
            }
            if (bytesToRet > 0 && bytesToRet < 64 && calls.Count <= 2)
                return AccessCheckVerdict.NoChecks;

            return AccessCheckVerdict.Unknown;
        }

        private static BufferValidation CheckBufferValidation(byte[] data, int handlerOffset,
            PeParser.PeHeaders headers, Dictionary<uint, string> iatMap)
        {
            var calls = FindCallTargets(data, handlerOffset, 4096, headers);

            bool hasProbe = false;
            bool hasLenCheck = false;

            foreach (var call in calls)
            {
                if (!call.IsIatCall || !iatMap.ContainsKey(call.TargetRva)) continue;
                string name = iatMap[call.TargetRva];

                if (name == "ProbeForRead" || name == "ProbeForWrite")
                    hasProbe = true;
                if (name == "MmIsAddressValid")
                    hasLenCheck = true;
            }

            // Look for __try/__except pattern (common structured exception handling in x64)
            // .pdata section contains exception handler info - presence of __C_specific_handler import
            if (iatMap.Values.Any(v => v == "__C_specific_handler"))
                hasLenCheck = true;

            if (hasProbe) return BufferValidation.ProperValidation;
            if (hasLenCheck) return BufferValidation.BasicValidation;

            // Check for length comparison patterns (CMP reg, [reg+offset] where offset = InputBufferLength)
            int scanEnd = Math.Min(handlerOffset + 4096, data.Length - 4);
            for (int i = handlerOffset; i < scanEnd; i++)
            {
                // CMP instructions with small immediates could be length checks
                // But this is too imprecise - mark as unknown unless we found probes
            }

            return BufferValidation.NoValidation;
        }

        private static bool CheckPreviousModeCheck(byte[] data, int handlerOffset,
            PeParser.PeHeaders headers, Dictionary<uint, string> iatMap)
        {
            var calls = FindCallTargets(data, handlerOffset, 4096, headers);
            foreach (var call in calls)
            {
                if (!call.IsIatCall || !iatMap.ContainsKey(call.TargetRva)) continue;
                string name = iatMap[call.TargetRva];
                if (name == "ExGetPreviousMode" || name == "KeGetPreviousMode")
                    return true;
            }
            return false;
        }

        private static bool IsValidIoctlCode(uint code)
        {
            uint deviceType = (code >> 16) & 0xFFFF;
            uint function = (code >> 2) & 0xFFF;
            if (function < 1 || function > 0xFFF) return false;
            if (deviceType == 0x22) return true; // FILE_DEVICE_UNKNOWN (most common)
            if (deviceType >= 0x8000 && deviceType <= 0x80FF) return true; // Custom device types
            if (deviceType == 0x09 || deviceType == 0x0C || deviceType == 0x12 ||
                deviceType == 0x21 || deviceType == 0x34) return true; // Other known types
            return false;
        }

        #endregion
    }
}
