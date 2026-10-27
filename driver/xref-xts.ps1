# XTS 交叉验证（内核侧 vs 救援工具侧）
#
# 目的：内核驱动最终用 Windows CNG 的 AES-ECB 实现加解密，救援工具用 Rust 的 aes crate。
#       两套代码由不同语言独立实现，必须产出**完全相同**的密文，否则"驱动坏了就救不回来"。
#
# 用法：跑本脚本生成向量 → 与 core/src/xts.rs 里的测试常量比对。
#       Rust 侧一旦改动算法，这里重跑就能立刻发现不一致。

$ErrorActionPreference = 'Stop'

$code = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class XtsXref
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string id, string impl, uint f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptCloseAlgorithmProvider(IntPtr h, uint f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptGenerateSymmetricKey(IntPtr a, out IntPtr k, IntPtr o, int co, byte[] s, int cs, uint f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptDestroyKey(IntPtr k);
    [DllImport("bcrypt.dll")]
    static extern int BCryptEncrypt(IntPtr k, byte[] i, int ci, IntPtr p, byte[] iv, int civ, byte[] o, int co, out int r, uint f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptDecrypt(IntPtr k, byte[] i, int ci, IntPtr p, byte[] iv, int civ, byte[] o, int co, out int r, uint f);

    // 用 CNG 的 AES-256-ECB 做一个"块函数"
    static byte[] Ecb(byte[] key, byte[] block, bool encrypt)
    {
        IntPtr a;
        if (BCryptOpenAlgorithmProvider(out a, "AES", null, 0) != 0) throw new Exception("open");
        try
        {
            IntPtr k;
            if (BCryptGenerateSymmetricKey(a, out k, IntPtr.Zero, 0, key, key.Length, 0) != 0) throw new Exception("genkey");
            try
            {
                byte[] o = new byte[16];
                int r;
                int st = encrypt
                    ? BCryptEncrypt(k, block, 16, IntPtr.Zero, null, 0, o, 16, out r, 0)
                    : BCryptDecrypt(k, block, 16, IntPtr.Zero, null, 0, o, 16, out r, 0);
                if (st != 0) throw new Exception("ecb 0x" + st.ToString("X8"));
                return o;
            }
            finally { BCryptDestroyKey(k); }
        }
        finally { BCryptCloseAlgorithmProvider(a, 0); }
    }

    static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] r = new byte[16];
        for (int i = 0; i < 16; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    // tweak = AES_ECB(key2, file_id[0..8] || block_index_be64)
    static byte[] Tweak(byte[] key2, byte[] fileId, ulong blockIndex)
    {
        byte[] input = new byte[16];
        Array.Copy(fileId, 0, input, 0, 8);
        byte[] bi = BitConverter.GetBytes(blockIndex);
        Array.Reverse(bi);                       // 转大端，与 Rust 的 to_be_bytes 一致
        Array.Copy(bi, 0, input, 8, 8);
        return Ecb(key2, input, true);
    }

    // C = AES_ECB(key1, P ^ T) ^ T
    static byte[] EncBlock(byte[] key1, byte[] t, byte[] p)
    {
        return Xor(Ecb(key1, Xor(p, t), true), t);
    }

    static byte[] DecBlock(byte[] key1, byte[] t, byte[] c)
    {
        return Xor(Ecb(key1, Xor(c, t), false), t);
    }

    static string Hex(byte[] b)
    {
        var sb = new StringBuilder();
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }

    public static string Run()
    {
        byte[] key = new byte[64];
        for (int i = 0; i < 64; i++) key[i] = (byte)i;

        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        Array.Copy(key, 0, key1, 0, 32);
        Array.Copy(key, 32, key2, 0, 32);

        byte[] fileId = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

        var sb = new StringBuilder();
        sb.AppendLine("key      = 000102...3f（64 字节）");
        sb.AppendLine("file_id  = 1122334455667788");
        sb.AppendLine();

        // 块 0：明文全 0；块 1：明文 0102...0f
        byte[] p0 = new byte[16];
        byte[] p1 = new byte[16];
        for (int i = 0; i < 16; i++) p1[i] = (byte)i;

        byte[] t0 = Tweak(key2, fileId, 0);
        byte[] t1 = Tweak(key2, fileId, 1);
        sb.AppendLine("tweak[0] = " + Hex(t0));
        sb.AppendLine("tweak[1] = " + Hex(t1));

        byte[] c0 = EncBlock(key1, t0, p0);
        byte[] c1 = EncBlock(key1, t1, p1);
        sb.AppendLine();
        sb.AppendLine("密文[0]  = " + Hex(c0) + "   ← 明文全 0");
        sb.AppendLine("密文[1]  = " + Hex(c1) + "   ← 明文 0001..0f");
        sb.AppendLine();

        // 解密验证
        byte[] d0 = DecBlock(key1, t0, c0);
        byte[] d1 = DecBlock(key1, t1, c1);
        sb.AppendLine("解密[0]  = " + Hex(d0) + (Hex(d0) == Hex(p0) ? "  ✅" : "  ❌"));
        sb.AppendLine("解密[1]  = " + Hex(d1) + (Hex(d1) == Hex(p1) ? "  ✅" : "  ❌"));

        // offset=64 起（块 4）单独解密，验证随机访问
        byte[] t4 = Tweak(key2, fileId, 4);
        byte[] p4 = new byte[16];
        for (int i = 0; i < 16; i++) p4[i] = (byte)(0xA0 + i);
        byte[] c4 = EncBlock(key1, t4, p4);
        sb.AppendLine();
        sb.AppendLine("块4(offset=64) 密文 = " + Hex(c4));
        sb.AppendLine("块4 单独解密       = " + Hex(DecBlock(key1, t4, c4)) + (Hex(DecBlock(key1, t4, c4)) == Hex(p4) ? "  ✅" : "  ❌"));

        return sb.ToString();
    }
}
'@

Add-Type -TypeDefinition $code -Language CSharp
Write-Host '=== 内核侧（CNG AES-256-ECB）算出的参考结果 ===' -ForegroundColor Cyan
[XtsXref]::Run()
Write-Host ''
Write-Host '把上面的 tweak/密文与 core/src/xts.rs 的交叉验证测试比对；不一致说明两侧算法已漂移。' -ForegroundColor Yellow
