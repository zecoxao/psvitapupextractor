// PS Vita PUP full unpack pipeline, ported from Team Molecule pup_fiction.py.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace VitaPupExtractor
{
    public static class VitaPup
    {
        static readonly string[] FSTYPE = {
            "unknown0","os0","unknown2","unknown3","vs0_chmod","unknown5","unknown6","unknown7",
            "pervasive8","boot_slb2","vs0","devkit_cp","motionC","bbmc","unknownE","motionF",
            "touch10","touch11","syscon12","syscon13","pervasive14","unknown15","vs0_tarpatch",
            "sa0","pd0","pervasive19","unknown1A","psp_emulist"
        };
        static readonly Dictionary<ulong, string> PupTypes = new Dictionary<ulong, string>{
            {0x100,"version.txt"},{0x101,"license.xml"},{0x200,"psp2swu.self"},{0x204,"cui_setupper.self"},
            {0x400,"package_scewm.wm"},{0x401,"package_sceas.as"},{0x2005,"UpdaterES1.CpUp"},{0x2006,"UpdaterES2.CpUp"},
        };

        public class Options
        {
            public bool ExtractFilesystems = true;   // 7z os0 (and vs0 if IncludeVs0)
            public bool IncludeVs0 = true;           // vs0 / vs0_tarpatch / vd0 (large)
            public bool DecryptSlb2 = true;
            public string SevenZip;                  // path to 7z.exe or null
            public string UnarzlExe;                 // path to unarzl.exe or null
        }

        // ENC key by firmware version (from PUP header fw @0x10).
        // 0xAA.. (random/placeholder) is used up to and including 3.69; 3.70 onward uses a non-random key.
        static byte[] EncKeyForFw(uint fw)
        {
            if (fw >= 0x03700000)   // 3.70+ (known value covers 3.70-3.74)
                return VKeyUtil.Hex("7CE42822813F360928801C59E01622AB");
            return VKeyUtil.Hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        }
        static readonly byte[] EncIv = VKeyUtil.Hex("AF5F2CB04AC1751ABF51CEF1C8096210");

        static readonly Dictionary<int, int> _typecount = new Dictionary<int, int>();
        static string MakeFilename(byte[] hdr, ulong filetype)
        {
            uint magic = LE.U32(hdr, 0), version = LE.U32(hdr, 4), flags = LE.U32(hdr, 8);
            ulong metaoffs = LE.U64(hdr, 0x10);
            if (magic == 0x454353 && version == 3 && flags == 0x30040)
            {
                int t = hdr[(int)metaoffs + 4];
                if (t < 0x1C) { int n = _typecount.ContainsKey(t) ? _typecount[t] : 0; _typecount[t] = n + 1; return string.Format("{0}-{1:D2}.pkg", FSTYPE[t], n); }
            }
            return string.Format("unknown-0x{0:x}.pkg", filetype);
        }

        public static void ExtractPup(string pup, string output, Options opt, VKeyStore[] stores, Action<string> log)
        {
            if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any())
                throw new Exception(output + " already exists and is not empty; remove it first");
            Directory.CreateDirectory(output);
            _typecount.Clear();

            byte[] all = File.ReadAllBytes(pup);
            if (!(all[0] == 'S' && all[1] == 'C' && all[2] == 'E' && all[3] == 'U' && all[4] == 'F'))
                throw new Exception("Invalid PUP (no SCEUF magic)");
            uint fw = LE.U32(all, 0x10);
            log(string.Format("PUP fw=0x{0:X8} build={1} files={2}", fw, LE.U32(all, 0x14), LE.U32(all, 0x18)));
            byte[] encKey = EncKeyForFw(fw);

            string pupDir = Path.Combine(output, "PUP"); Directory.CreateDirectory(pupDir);
            PupExtractFiles(all, pupDir, log);

            string decDir = Path.Combine(output, "PUP_dec"); Directory.CreateDirectory(decDir);
            PupDecryptPackages(pupDir, decDir, stores, log);

            // SLB2
            string slb2Seg = Path.Combine(decDir, "boot_slb2-00.pkg.seg02");
            if (opt.DecryptSlb2 && File.Exists(slb2Seg))
            {
                string slb2Dir = Path.Combine(output, "SLB2"); Directory.CreateDirectory(slb2Dir);
                Slb2Extract(slb2Seg, slb2Dir, log);
                string slb2Dec = Path.Combine(output, "SLB2_dec"); Directory.CreateDirectory(slb2Dec);
                Slb2Decrypt(slb2Dir, slb2Dec, encKey, EncIv, stores, opt.UnarzlExe, log);
            }

            // filesystems
            if (opt.ExtractFilesystems)
            {
                if (string.IsNullOrEmpty(opt.SevenZip) || !File.Exists(opt.SevenZip))
                    log("[!] 7-Zip not found; skipping os0/vs0 filesystem extraction (os0.bin/vs0.bin left raw).");
                else
                {
                    ExtractFs(output, opt.SevenZip, opt.IncludeVs0, log);
                    Directory.CreateDirectory(Path.Combine(output, "fs_dec"));
                    DecryptOs0(output, stores, log);
                    if (opt.IncludeVs0) DecryptVs0(output, stores, log);
                    else log("  (vs0 skipped - unchecked)");
                }
            }
            log("\nDone.");
        }

        static void PupExtractFiles(byte[] all, string pupDir, Action<string> log)
        {
            log("\n== Extract PUP files ==");
            uint cnt = LE.U32(all, 0x18);
            for (uint x = 0; x < cnt; x++)
            {
                long rec = 0x80 + (long)x * 0x20;
                ulong filetype = LE.U64(all, rec), offset = LE.U64(all, rec + 8), length = LE.U64(all, rec + 16);
                string name = PupTypes.ContainsKey(filetype) ? PupTypes[filetype] : null;
                if (name == null) { byte[] hdr = new byte[0x1000]; Array.Copy(all, (long)offset, hdr, 0, 0x1000); name = MakeFilename(hdr, filetype); }
                byte[] fd = new byte[length]; Array.Copy(all, (long)offset, fd, 0, (long)length);
                File.WriteAllBytes(Path.Combine(pupDir, name), fd);
                log("  - " + name);
            }
        }

        static void PupDecryptPackages(string src, string dst, VKeyStore[] stores, Action<string> log)
        {
            log("\n== Decrypt packages ==");
            foreach (string f in Directory.GetFiles(src, "*.pkg").OrderBy(x => x))
            {
                string name = Path.GetFileName(f);
                try
                {
                    string store; var segs = VitaSce.SceDecrypt(File.ReadAllBytes(f), stores, true, null, out store);
                    foreach (var kv in segs) File.WriteAllBytes(Path.Combine(dst, string.Format("{0}.seg{1:D2}", name, kv.Key)), kv.Value);
                    log(string.Format("  {0,-22} [{1}]", name, store));
                }
                catch (Exception ex) { log(string.Format("  [!] {0}: {1}", name, ex.Message)); }
            }
            foreach (string name in new[] { "cui_setupper.self", "psp2swu.self" })
            {
                string f = Path.Combine(src, name); if (!File.Exists(f)) continue;
                try { string store; byte[] elf = VitaSce.Self2Elf(File.ReadAllBytes(f), new byte[16], stores, true, null, out store); File.WriteAllBytes(Path.Combine(dst, name.Replace(".self", ".elf")), elf); log(string.Format("  {0,-22} [{1}] -> elf", name, store)); }
                catch (Exception ex) { log(string.Format("  [!] {0}: {1}", name, ex.Message)); }
            }
            JoinFiles(dst, "os0-*.pkg.seg02", Path.Combine(dst, "os0.bin"));
            JoinFiles(dst, "vs0-*.pkg.seg02", Path.Combine(dst, "vs0.bin"));
        }

        static void JoinFiles(string dir, string mask, string outPath)
        {
            var files = Directory.GetFiles(dir, mask).OrderBy(x => x).ToList();
            if (files.Count == 0) return;
            using (var o = new FileStream(outPath, FileMode.Create, FileAccess.Write))
                foreach (var f in files) { byte[] b = File.ReadAllBytes(f); o.Write(b, 0, b.Length); }
            foreach (var f in files) File.Delete(f);
        }

        static void Slb2Extract(string src, string dst, Action<string> log)
        {
            log("\n== SLB2 extract ==");
            byte[] d = File.ReadAllBytes(src);
            if (LE.U32(d, 0) != 0x32424C53) throw new Exception("Invalid SLB2");
            uint fileCount = LE.U32(d, 0xc);
            for (int x = 0; x < fileCount; x++)
            {
                long e = 0x20 + x * 0x30;
                uint blockOffset = LE.U32(d, e), filesize = LE.U32(d, e + 4);
                int nl = 0; while (nl < 0x20 && d[e + 0x10 + nl] != 0) nl++;
                string name = System.Text.Encoding.ASCII.GetString(d, (int)(e + 0x10), nl);
                byte[] fd = new byte[filesize]; Array.Copy(d, (long)blockOffset * 0x200, fd, 0, filesize);
                File.WriteAllBytes(Path.Combine(dst, name), fd);
                log("  - " + name);
            }
        }

        static void EncDecrypt(string src, string dst, byte[] encKey, byte[] encIv)
        {
            byte[] data = File.ReadAllBytes(src);
            if (LE.U32(data, 0) != 0x64B2C8E5) throw new Exception("enc format invalid");
            uint offset = LE.U32(data, 4), dataSize = LE.U32(data, 0x10);
            byte[] dec = VCrypto.CbcDecrypt(encKey, encIv, data, offset, (int)dataSize);
            File.WriteAllBytes(dst, dec);
        }

        static void Slb2Decrypt(string src, string dst, byte[] encKey, byte[] encIv, VKeyStore[] stores, string unarzlExe, Action<string> log)
        {
            log("\n== SLB2 decrypt ==");
            foreach (string name in new[] { "second_loader.enc", "secure_kernel.enc" })
            {
                string f = Path.Combine(src, name); if (!File.Exists(f)) continue;
                try { EncDecrypt(f, Path.Combine(dst, name.Replace(".enc", ".bin")), encKey, encIv); log("  enc " + name); }
                catch (Exception ex) { log("  [!] " + name + ": " + ex.Message); }
            }
            foreach (string name in new[] { "kernel_boot_loader.self", "prog_rvk.srvk" })
            {
                string f = Path.Combine(src, name); if (!File.Exists(f)) continue;
                try { string store; var segs = VitaSce.SceDecrypt(File.ReadAllBytes(f), stores, true, null, out store); foreach (var kv in segs) File.WriteAllBytes(Path.Combine(dst, string.Format("{0}.seg{1:D2}", name, kv.Key)), kv.Value); log(string.Format("  sce {0} [{1}]", name, store)); }
                catch (Exception ex) { log("  [!] " + name + ": " + ex.Message); }
            }
            foreach (string name in new[] { "kprx_auth_sm.self" })
            {
                string f = Path.Combine(src, name); if (!File.Exists(f)) continue;
                try { string store; byte[] elf = VitaSce.Self2Elf(File.ReadAllBytes(f), new byte[16], stores, false, null, out store); File.WriteAllBytes(Path.Combine(dst, name.Replace(".self", ".elf")), elf); log(string.Format("  self2elf {0} [{1}]", name, store)); }
                catch (Exception ex) { log("  [!] " + name + ": " + ex.Message); }
            }
            string seg03 = Path.Combine(dst, "kernel_boot_loader.self.seg03");
            if (File.Exists(seg03))
            {
                if (!string.IsNullOrEmpty(unarzlExe) && File.Exists(unarzlExe))
                { RunTool(unarzlExe, new[] { seg03, Path.Combine(dst, "nsbl.bin") }, log); log("  unarzl nsbl.bin"); }
                else log("  [!] unarzl.exe not found; skipping nsbl.bin");
            }
        }

        static void ExtractFs(string output, string sevenZip, bool includeVs0, Action<string> log)
        {
            log("\n== Extract filesystems (7-Zip) ==");
            string fsOut = Path.Combine(output, "fs"); Directory.CreateDirectory(fsOut);
            var parts = includeVs0 ? new[] { "os0", "vs0", "vd0" } : new[] { "os0" };
            foreach (string part in parts)
            {
                string inBin = Path.Combine(output, "PUP_dec", part + ".bin");
                if (!File.Exists(inBin)) { if (part != "vd0") log("  [!] " + part + ".bin missing"); continue; }
                string outDir = Path.Combine(fsOut, part); Directory.CreateDirectory(outDir);
                RunTool(sevenZip, new[] { "x", "-y", inBin, "-o" + outDir }, null);
                log("  extracted " + part);
            }
            if (includeVs0)
            {
                string tarpatchOut = Path.Combine(fsOut, "vs0_tarpatch");
                foreach (string f in Directory.GetFiles(Path.Combine(output, "PUP_dec"), "vs0_tarpatch-*.pkg.seg02"))
                { RunTool(sevenZip, new[] { "x", "-y", f, "-o" + tarpatchOut }, null); log("  tarpatch " + Path.GetFileName(f)); }
            }
        }

        static readonly string[] Os0Configs = { "psp2config_dolce.skprx", "psp2config_vita.skprx", "psp2config.skprx" };

        static void DecryptOs0(string output, VKeyStore[] stores, Action<string> log)
        {
            log("\n== Decrypt os0 ==");
            string inDir = Path.Combine(output, "fs", "os0"), outDir = Path.Combine(output, "fs_dec", "os0");
            if (!Directory.Exists(inDir)) return;
            DecryptSelfs(inDir, outDir, Os0Configs, stores, log);
            foreach (string name in Os0Configs)
            {
                string f = Path.Combine(inDir, name); if (!File.Exists(f)) continue;
                try { Directory.CreateDirectory(outDir); string store; var segs = VitaSce.SceDecrypt(File.ReadAllBytes(f), stores, true, null, out store); foreach (var kv in segs) File.WriteAllBytes(Path.Combine(outDir, string.Format("{0}.seg{1:D2}", name, kv.Key)), kv.Value); log("  sce " + name); }
                catch (Exception ex) { log("  [!] " + name + ": " + ex.Message); }
            }
        }

        static void DecryptVs0(string output, VKeyStore[] stores, Action<string> log)
        {
            log("\n== Decrypt vs0 ==");
            foreach (string part in new[] { "vs0", "vs0_tarpatch" })
            {
                string inDir = Path.Combine(output, "fs", part), outDir = Path.Combine(output, "fs_dec", part);
                if (!Directory.Exists(inDir)) continue;
                DecryptSelfs(inDir, outDir, null, stores, log);
            }
        }

        static void DecryptSelfs(string inDir, string outDir, string[] blacklist, VKeyStore[] stores, Action<string> log)
        {
            var bl = new HashSet<string>(blacklist ?? new string[0], StringComparer.OrdinalIgnoreCase);
            foreach (string f in Directory.GetFiles(inDir, "*", SearchOption.AllDirectories))
            {
                string filename = Path.GetFileName(f);
                string ext = Path.GetExtension(filename).ToLowerInvariant();
                bool match = (ext == ".self" || ext == ".skprx" || ext == ".suprx" || filename == "eboot.bin") && !bl.Contains(filename);
                if (!match) continue;
                string rel = GetRel(inDir, Path.GetDirectoryName(f));
                string od = Path.Combine(outDir, rel); Directory.CreateDirectory(od);
                string name = Path.GetFileNameWithoutExtension(filename);
                try { string store; byte[] elf = VitaSce.Self2Elf(File.ReadAllBytes(f), new byte[16], stores, false, null, out store); File.WriteAllBytes(Path.Combine(od, name + ".elf"), elf); log("  self2elf " + Path.Combine(rel, filename)); }
                catch (Exception ex) { log("  [!] no key " + filename + ": " + ex.Message); }
            }
        }

        static string GetRel(string root, string path)
        {
            if (path.Length <= root.Length) return "";
            string r = path.Substring(root.Length).TrimStart('\\', '/');
            return r;
        }

        static void RunTool(string exe, string[] args, Action<string> log)
        {
            var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var a in args) psi.Arguments += "\"" + a + "\" ";
            using (var p = Process.Start(psi)) { p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(); }
        }

        public static string FindSevenZip()
        {
            foreach (string p in new[] { @"C:\Program Files\7-Zip\7z.exe", @"C:\Program Files (x86)\7-Zip\7z.exe" })
                if (File.Exists(p)) return p;
            return null;
        }
    }
}
