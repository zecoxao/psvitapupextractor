// PS Vita SCE/SELF decryption, ported from Team Molecule sceutils
// (scetypes.py, sceutils.py, self2elf.py, scedecrypt.py).
// Little-endian. Tries keystores in order (proto -> internal -> external).
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace VitaPupExtractor
{
    static class LE
    {
        public static ushort U16(byte[] b, long o) { return BitConverter.ToUInt16(b, (int)o); }
        public static uint U32(byte[] b, long o) { return BitConverter.ToUInt32(b, (int)o); }
        public static ulong U64(byte[] b, long o) { return BitConverter.ToUInt64(b, (int)o); }
        public static int I32(byte[] b, long o) { return BitConverter.ToInt32(b, (int)o); }
    }

    static class VCrypto
    {
        static Aes Ecb(byte[] key) { var a = Aes.Create(); a.Mode = CipherMode.ECB; a.Padding = PaddingMode.None; a.KeySize = key.Length * 8; a.Key = key; return a; }

        // AES-CBC decrypt a copy of src[off..off+len) (len multiple of 16). key 16 or 32 bytes.
        public static byte[] CbcDecrypt(byte[] key, byte[] iv, byte[] src, long off, int len)
        {
            using (var a = Aes.Create())
            {
                a.Mode = CipherMode.CBC; a.Padding = PaddingMode.None; a.KeySize = key.Length * 8; a.Key = key; a.IV = (byte[])iv.Clone();
                byte[] slice = new byte[len]; Array.Copy(src, off, slice, 0, len);
                using (var d = a.CreateDecryptor()) return d.TransformFinalBlock(slice, 0, len);
            }
        }

        // AES-128-CTR, full 128-bit big-endian counter starting at iv (matches PyCrypto Counter.new(128, iv)).
        public static byte[] Ctr128(byte[] key, byte[] iv, byte[] data)
        {
            byte[] ctr = (byte[])iv.Clone();
            byte[] outp = new byte[data.Length];
            using (var a = Ecb(key))
            using (var enc = a.CreateEncryptor())
            {
                byte[] ks = new byte[16];
                for (int i = 0; i < data.Length; i++)
                {
                    if ((i & 0xf) == 0)
                    {
                        enc.TransformBlock(ctr, 0, 16, ks, 0);
                        for (int j = 15; j >= 0; j--) { if (++ctr[j] != 0) break; }
                    }
                    outp[i] = (byte)(data[i] ^ ks[i & 0xf]);
                }
            }
            return outp;
        }
    }

    static class VZlib
    {
        // zlib stream -> inflate fully (skip 2-byte header).
        public static byte[] Inflate(byte[] input, long off, long len)
        {
            using (var ms = new MemoryStream(input, (int)(off + 2), (int)(len - 2)))
            using (var ds = new DeflateStream(ms, CompressionMode.Decompress))
            using (var outp = new MemoryStream())
            {
                byte[] buf = new byte[1 << 16]; int r;
                while ((r = ds.Read(buf, 0, buf.Length)) > 0) outp.Write(buf, 0, r);
                return outp.ToArray();
            }
        }
    }

    // ---- headers ----
    class SceHeader
    {
        public const int Size = 32;
        public uint magic, version; public byte platform, key_revision; public ushort sce_type_raw;
        public uint metadata_offset; public ulong header_length, data_length;
        public VSceType sce_type;
        public SceHeader(byte[] d, int o = 0)
        {
            magic = LE.U32(d, o); version = LE.U32(d, o + 4); platform = d[o + 8]; key_revision = d[o + 9];
            sce_type_raw = LE.U16(d, o + 10); metadata_offset = LE.U32(d, o + 12);
            header_length = LE.U64(d, o + 16); data_length = LE.U64(d, o + 24);
            if (magic != 0x00454353) throw new Exception("Invalid SCE magic");
            if (version != 3) throw new Exception("Unknown SCE version");
            sce_type = (VSceType)sce_type_raw;
        }
    }

    public static class VitaSce
    {
        public static bool IsSce(byte[] b, int o = 0) { return b.Length >= o + 4 && LE.U32(b, o) == 0x00454353; }

        struct Seg { public ulong offset; public int idx; public ulong size; public bool compressed; public byte[] key, iv; }

        // get_key_type
        static void GetKeyType(byte[] d, SceHeader sce, out long sysver, out VSelfType selftype)
        {
            if (sce.sce_type == VSceType.SELF)
            {
                long appinfo_offset = (long)LE.U64(d, 32 + 24); // SelfHeader.appinfo_offset (4th Q)
                sysver = (long)LE.U64(d, appinfo_offset + 16);
                selftype = (VSelfType)LE.U32(d, appinfo_offset + 12);
            }
            else if (sce.sce_type == VSceType.SRVK)
            {
                long o = (long)sce.header_length; sysver = (long)LE.U64(d, o + 8); selftype = VSelfType.NONE;
            }
            else if (sce.sce_type == VSceType.SPKG)
            {
                long o = (long)sce.header_length; ulong update_version = LE.U64(d, o + 16); sysver = (long)(update_version << 16); selftype = VSelfType.NONE;
            }
            else { sysver = -1; selftype = VSelfType.NONE; }
        }

        // get_segments with keystore fallback. Returns segments keyed by phdr index.
        static Dictionary<int, Seg> GetSegments(byte[] d, SceHeader sce, long sysver, VSelfType selftype, int npdrmtype, byte[] klictxt, VKeyStore[] stores, Action<string> log, out string usedStore)
        {
            long metaStart = (long)sce.metadata_offset + 48;
            int metaLen = (int)((long)sce.header_length - (long)sce.metadata_offset - 48);
            byte[] dat = new byte[metaLen]; Array.Copy(d, metaStart, dat, 0, metaLen);

            byte[] metaInfoDec = null; usedStore = null;
            foreach (var store in stores)
            {
                byte[] key, iv;
                if (!store.TryGet(VKeyType.METADATA, sce.sce_type, sysver, sce.key_revision, selftype, out key, out iv)) continue;

                byte[] dec_in;
                if (selftype == VSelfType.APP)
                {
                    int keytype = sce.key_revision >= 2 ? 1 : 0;
                    byte[] npk, npiv;
                    if (!store.TryGet(VKeyType.NPDRM, sce.sce_type, sysver, keytype, VSelfType.APP, out npk, out npiv)) continue;
                    byte[] predec = VCrypto.CbcDecrypt(npk, npiv, klictxt, 0, 16);
                    dec_in = VCrypto.CbcDecrypt(predec, npiv, dat, 0, 64);
                }
                else dec_in = new byte[64] /*copy*/;
                if (selftype != VSelfType.APP) Array.Copy(dat, 0, dec_in, 0, 64);

                byte[] dec = VCrypto.CbcDecrypt(key, iv, dec_in, 0, 64);
                // MetadataInfo padding check: bytes[16:32] and [48:64] must be zero
                bool ok = true;
                for (int j = 16; j < 32 && ok; j++) if (dec[j] != 0) ok = false;
                for (int j = 48; j < 64 && ok; j++) if (dec[j] != 0) ok = false;
                if (!ok) continue;
                metaInfoDec = dec; usedStore = store.Name; break;
            }
            if (metaInfoDec == null) throw new Exception("Cannot find key/iv for this SCE file (all keystores failed)");
            if (log != null) log("    [key: " + usedStore + "]");

            byte[] miKey = new byte[16]; Array.Copy(metaInfoDec, 0, miKey, 0, 16);
            byte[] miIv = new byte[16]; Array.Copy(metaInfoDec, 32, miIv, 0, 16);

            byte[] contents = VCrypto.CbcDecrypt(miKey, miIv, dat, 64, metaLen - 64);
            // MetadataHeader
            uint section_count = LE.U32(contents, 12);
            uint key_count = LE.U32(contents, 16);
            int hdrSize = 32;
            int vaultStart = hdrSize + (int)section_count * 48;
            byte[][] vault = new byte[key_count][];
            for (int x = 0; x < key_count; x++) { vault[x] = new byte[16]; Array.Copy(contents, vaultStart + 16 * x, vault[x], 0, 16); }

            var segs = new Dictionary<int, Seg>();
            for (int i = 0; i < section_count; i++)
            {
                int b = hdrSize + i * 48;
                ulong offset = LE.U64(contents, b);        // @0
                ulong size = LE.U64(contents, b + 8);      // @8
                int seg_idx = LE.I32(contents, b + 20);    // @20
                uint encryption = LE.U32(contents, b + 32);// @32
                int key_idx = LE.I32(contents, b + 36);    // @36
                int iv_idx = LE.I32(contents, b + 40);     // @40
                uint compression = LE.U32(contents, b + 44);// @44
                if (encryption == 3) // AES128CTR
                    segs[i] = new Seg { offset = offset, idx = seg_idx, size = size, compressed = compression == 2, key = vault[key_idx], iv = vault[iv_idx] };
            }
            return segs;
        }

        // self2elf
        public static byte[] Self2Elf(byte[] d, byte[] klictxt, VKeyStore[] stores, bool ignoreSysver, Action<string> log, out string usedStore)
        {
            usedStore = null;
            var sce = new SceHeader(d);
            // SelfHeader @32
            long self_base = 32;
            long appinfo_offset = (long)LE.U64(d, self_base + 24);
            long elf_offset = (long)LE.U64(d, self_base + 32);
            long phdr_offset = (long)LE.U64(d, self_base + 40);
            long segment_info_offset = (long)LE.U64(d, self_base + 56);
            long controlinfo_offset = (long)LE.U64(d, self_base + 72);

            long sysver = ignoreSysver ? -1 : (long)LE.U64(d, appinfo_offset + 16);
            VSelfType selftype = (VSelfType)LE.U32(d, appinfo_offset + 12);

            // walk control info for npdrm type
            int npdrmtype = 0;
            long ci = controlinfo_offset;
            uint ctype1 = LE.U32(d, ci); long csize1 = (long)LE.U64(d, ci + 8); // SceControlInfo (type,size,more)
            long ci_off = 16;
            if (ctype1 == 4 /*DIGEST_SHA256*/) ci_off += 64;
            uint ctype2 = LE.U32(d, controlinfo_offset + ci_off);
            ci_off += 16;
            if (ctype2 == 5 /*NPDRM_VITA*/) npdrmtype = (int)LE.U32(d, controlinfo_offset + ci_off + 8);

            // ELF header
            var outp = new MemoryStream();
            int elfHdrSize = 52;
            outp.Write(d, (int)elf_offset, elfHdrSize);
            ushort e_phnum = LE.U16(d, elf_offset + 44);
            long at = elfHdrSize;

            var phOff = new long[e_phnum]; var phFilesz = new long[e_phnum];
            var segOff = new ulong[e_phnum]; var segSize = new ulong[e_phnum];
            var segPlainNo = new bool[e_phnum]; var segComp = new bool[e_phnum];
            bool encrypted = false;
            for (int i = 0; i < e_phnum; i++)
            {
                long p = phdr_offset + i * 32;
                phOff[i] = LE.U32(d, p + 4);     // p_offset
                phFilesz[i] = LE.U32(d, p + 16); // p_filesz
                outp.Write(d, (int)p, 32);
                at += 32;
                long s = segment_info_offset + i * 32;
                segOff[i] = LE.U64(d, s); segSize[i] = LE.U64(d, s + 8);
                uint comp = LE.U32(d, s + 16); uint plain = LE.U32(d, s + 24);
                segComp[i] = comp == 2; segPlainNo[i] = plain == 1; // SecureBool.NO==1
                if (segPlainNo[i]) encrypted = true;
            }

            Dictionary<int, Seg> scesegs = null;
            if (encrypted) scesegs = GetSegments(d, sce, sysver, selftype, npdrmtype, klictxt, stores, log, out usedStore);

            for (int i = 0; i < e_phnum; i++)
            {
                int idx = scesegs != null ? scesegs[i].idx : i;
                if (phFilesz[idx] == 0) continue;
                long padLen = phOff[idx] - at;
                if (padLen < 0) throw new Exception("ELF p_offset invalid");
                if (padLen > 0) { outp.Write(new byte[padLen], 0, (int)padLen); at += padLen; }
                byte[] dat = new byte[segSize[idx]]; Array.Copy(d, (long)segOff[idx], dat, 0, (long)segSize[idx]);
                if (segPlainNo[idx]) dat = VCrypto.Ctr128(scesegs[i].key, scesegs[i].iv, dat);
                if (segComp[idx]) dat = VZlib.Inflate(dat, 0, dat.Length);
                outp.Write(dat, 0, dat.Length);
                at += dat.Length;
            }
            return outp.ToArray();
        }

        // scedecrypt -> list of (segment index, bytes)
        public static List<KeyValuePair<int, byte[]>> SceDecrypt(byte[] d, VKeyStore[] stores, bool decompress, Action<string> log, out string usedStore)
        {
            var sce = new SceHeader(d);
            long sysver; VSelfType selftype; GetKeyType(d, sce, out sysver, out selftype);
            var scesegs = GetSegments(d, sce, sysver, selftype, 0, new byte[16], stores, log, out usedStore);
            var res = new List<KeyValuePair<int, byte[]>>();
            foreach (var kv in scesegs)
            {
                var sg = kv.Value;
                byte[] dat = new byte[sg.size]; Array.Copy(d, (long)sg.offset, dat, 0, (long)sg.size);
                dat = VCrypto.Ctr128(sg.key, sg.iv, dat);
                if (decompress && sg.compressed) dat = VZlib.Inflate(dat, 0, dat.Length);
                res.Add(new KeyValuePair<int, byte[]>(kv.Key, dat));
            }
            return res;
        }
    }
}
