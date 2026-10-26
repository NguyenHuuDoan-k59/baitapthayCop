using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

ECDsa? ecc = null;

bool NeedKey()
{
    if (ecc != null) return true;
    Console.WriteLine("Chưa có khóa. Hãy chọn menu 1 (sinh khóa) trước.");
    return false;
}

string Ask(string prompt, string def = "")
{
    Console.Write(prompt);
    string s = (Console.ReadLine() ?? "").Trim().Trim('"');
    return s.Length == 0 ? def : s;
}

while (true)
{
    Console.WriteLine();
    Console.WriteLine("=== BÀI 2: ECC / SHA-512 / ECDSA ===");
    Console.WriteLine("1. Sinh khóa ECC (P-256 / P-384 / P-521)");
    Console.WriteLine("2. Xuất public.pem và private.pem");
    Console.WriteLine("3. Xem PEM (cây ASN.1 / DER)");
    Console.WriteLine("4. Nhập PEM, hiện Qx, Qy, d");
    Console.WriteLine("5. Mã hóa lai ECDH + HKDF + ChaCha20-Poly1305");
    Console.WriteLine("6. Giải mã bằng private key");
    Console.WriteLine("7. Đo tốc độ (ECC so với RSA)");
    Console.WriteLine("8. SHA-512 và hiệu ứng thác đổ");
    Console.WriteLine("9. Chữ ký ECDSA (ngẫu nhiên và xác định)");
    Console.WriteLine("0. Thoát");
    Console.Write("Chọn: ");

    string? choice = Console.ReadLine()?.Trim();
    try
    {
        switch (choice)
        {
            case "1":
            {
                string c = Ask("Đường cong (256 / 384 / 521) [256]: ", "256");
                int bits = c == "384" ? 384 : c == "521" ? 521 : 256;
                ecc?.Dispose();
                ecc = ECDsa.Create(Helpers.CurveByBits(bits));
                var prm = ecc.ExportParameters(false);
                Console.WriteLine($"Đã sinh khóa ECC, đường cong {Helpers.CurveName(ecc.KeySize)} ({ecc.KeySize} bit).");
                Console.WriteLine($"  Qx = {Convert.ToHexString(prm.Q.X!)}");
                Console.WriteLine($"  Qy = {Convert.ToHexString(prm.Q.Y!)}");
                break;
            }

            case "2":
                if (!NeedKey()) break;
                File.WriteAllText("public.pem", ecc!.ExportSubjectPublicKeyInfoPem());
                File.WriteAllText("private.pem", ecc.ExportPkcs8PrivateKeyPem());
                Console.WriteLine($"Đã ghi {Path.GetFullPath("public.pem")} (BEGIN PUBLIC KEY, X.509 SPKI)");
                Console.WriteLine($"Đã ghi {Path.GetFullPath("private.pem")} (BEGIN PRIVATE KEY, PKCS#8)");
                break;

            case "3":
            {
                string path = Ask("File PEM cần xem [public.pem]: ", "public.pem");
                if (!File.Exists(path)) { Console.WriteLine("Không thấy file."); break; }
                Asn1.DumpPem(File.ReadAllText(path));
                break;
            }

            case "4":
            {
                string path = Ask("File PEM cần nhập [public.pem]: ", "public.pem");
                if (!File.Exists(path)) { Console.WriteLine("Không thấy file."); break; }
                Helpers.ImportAndShow(File.ReadAllText(path));
                break;
            }

            case "5":
                Ecies.EncryptMenu(Ask);
                break;

            case "6":
                Ecies.DecryptMenu(Ask);
                break;

            case "7":
            {
                int iters = int.TryParse(Ask("Số lần lặp mỗi phép thử [200]: ", "200"), out int n) && n > 0 ? n : 200;
                Bench.Run(iters);
                break;
            }

            case "8":
                Sha512Lab.Run();
                break;

            case "9":
                if (!NeedKey()) break;
                Signatures.Run(ecc!, Ask);
                break;

            case "0":
                return;

            default:
                Console.WriteLine("Lựa chọn không hợp lệ.");
                break;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("Lỗi: " + ex.Message);
    }
}

// ============================================================ tiện ích chung
static class Helpers
{
    public static ECCurve CurveByBits(int bits) => bits switch
    {
        384 => ECCurve.NamedCurves.nistP384,
        521 => ECCurve.NamedCurves.nistP521,
        _ => ECCurve.NamedCurves.nistP256
    };

    public static string CurveName(int bits) => bits switch
    {
        384 => "nistP384 (secp384r1)",
        521 => "nistP521 (secp521r1)",
        _ => "nistP256 (prime256v1)"
    };

    public static BigInteger Big(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);

    public static byte[] PemToDer(string pem, out string label)
    {
        var lines = pem.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        label = lines[0].Replace("-----BEGIN ", "").Replace("-----", "").Trim();
        string b64 = string.Concat(lines.Where(l => !l.StartsWith("-----")));
        return Convert.FromBase64String(b64);
    }

    public static void ImportAndShow(string pem)
    {
        bool isPrivate = pem.Contains("PRIVATE KEY");
        using var e = ECDsa.Create();
        e.ImportFromPem(pem);
        var prm = e.ExportParameters(isPrivate);
        Console.WriteLine(isPrivate ? "Đây là PRIVATE key." : "Đây là PUBLIC key.");
        Console.WriteLine($"Đường cong : {CurveName(e.KeySize)}");
        Console.WriteLine($"Qx ({Big(prm.Q.X!).GetBitLength()} bit): {Convert.ToHexString(prm.Q.X!)}");
        Console.WriteLine($"Qy ({Big(prm.Q.Y!).GetBitLength()} bit): {Convert.ToHexString(prm.Q.Y!)}");
        if (isPrivate)
            Console.WriteLine($"d  ({Big(prm.D!).GetBitLength()} bit): {Convert.ToHexString(prm.D!)}");
        Console.WriteLine("Kiểm tra Q nằm trên đường cong y² = x³ + ax + b (mod p): " + OnCurve(e, prm));
    }

    static string OnCurve(ECDsa e, ECParameters prm)
    {
        try
        {
            var ex = e.ExportExplicitParameters(false);
            BigInteger p = Big(ex.Curve.Prime!), a = Big(ex.Curve.A!), b = Big(ex.Curve.B!);
            BigInteger x = Big(prm.Q.X!), y = Big(prm.Q.Y!);
            bool ok = ((y * y - (x * x * x + a * x + b)) % p).IsZero;
            return ok ? "ĐÚNG (điểm hợp lệ)" : "SAI (điểm không thuộc đường cong)";
        }
        catch (Exception)
        {
            return "không xuất được tham số đường cong trên nền tảng này; việc nạp khóa thành công nghĩa là .NET đã tự kiểm tra điểm hợp lệ.";
        }
    }

    public static int BitDiff(byte[] a, byte[] b)
    {
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return diff;
    }

    public static byte[] Concat(params byte[][] parts)
    {
        var r = new byte[parts.Sum(p => p.Length)];
        int off = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, off, p.Length); off += p.Length; }
        return r;
    }
}

// ============================================================ ASN.1 / DER
static class Asn1
{
    static readonly Dictionary<string, string> OidNames = new()
    {
        ["1.2.840.10045.2.1"] = "id-ecPublicKey (khóa công khai ECC)",
        ["1.2.840.10045.3.1.7"] = "prime256v1 = nistP256 = secp256r1",
        ["1.3.132.0.34"] = "secp384r1 = nistP384",
        ["1.3.132.0.35"] = "secp521r1 = nistP521",
    };

    public static void DumpPem(string pem)
    {
        byte[] der = Helpers.PemToDer(pem, out string label);
        string b64 = Convert.ToBase64String(der);
        Console.WriteLine($"Nhãn PEM: {label}");
        Console.WriteLine($"DER dài {der.Length} byte, base64 dài {b64.Length} ký tự (4 ký tự base64 = 3 byte).");
        Console.WriteLine("Mỗi dòng: [offset] byte Tag + Length -> ý nghĩa");
        Walk(der, 0, der.Length, 0);
    }

    static string TagName(byte tag) => tag switch
    {
        0x30 => "SEQUENCE",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        _ when (tag & 0xC0) == 0x80 => $"[{tag & 0x1F}] context-specific",
        _ => $"tag 0x{tag:X2}"
    };

    static string DecodeOid(byte[] d, int pos, int len)
    {
        var sb = new StringBuilder();
        sb.Append(d[pos] / 40).Append('.').Append(d[pos] % 40);
        long val = 0;
        for (int i = pos + 1; i < pos + len; i++)
        {
            val = (val << 7) | (uint)(d[i] & 0x7F);
            if ((d[i] & 0x80) == 0) { sb.Append('.').Append(val); val = 0; }
        }
        return sb.ToString();
    }

    static void Walk(byte[] d, int pos, int end, int depth)
    {
        string ind = new string(' ', depth * 2);
        while (pos < end)
        {
            int start = pos;
            byte tag = d[pos++];
            int len = d[pos++];
            if (len >= 0x80)
            {
                int nb = len & 0x7F;
                len = 0;
                for (int i = 0; i < nb; i++) len = (len << 8) | d[pos++];
            }
            int hdr = pos - start;
            if (pos + len > end)
            {
                Console.WriteLine($"{ind}[{start,4}] cấu trúc không hợp lệ (độ dài vượt quá dữ liệu)");
                return;
            }
            string hdrHex = BitConverter.ToString(d, start, hdr).Replace('-', ' ');
            Console.WriteLine($"{ind}[{start,4}] {hdrHex,-12} -> {TagName(tag)}, dài {len} byte");

            bool constructed = (tag & 0x20) != 0;
            if (constructed)
            {
                Walk(d, pos, pos + len, depth + 1);
            }
            else if (tag == 0x06)
            {
                string oid = DecodeOid(d, pos, len);
                OidNames.TryGetValue(oid, out string? name);
                Console.WriteLine($"{ind}      OID {oid}" + (name != null ? $"  = {name}" : ""));
            }
            else if (tag == 0x02)
            {
                string hex = Convert.ToHexString(d, pos, len);
                string note = len == 1 ? "  (version)" : (d[pos] == 0 && len > 1 ? "  (có byte 00 đầu để không bị hiểu là số âm)" : "");
                Console.WriteLine($"{ind}      = {hex}{note}");
            }
            else if (tag == 0x03)
            {
                int unused = d[pos];
                Console.WriteLine($"{ind}      số bit thừa = {unused}");
                if (len > 2 && d[pos + 1] == 0x04)
                {
                    int cl = (len - 2) / 2;
                    Console.WriteLine($"{ind}      điểm KHÔNG NÉN: 04 || X || Y, mỗi tọa độ {cl} byte");
                    Console.WriteLine($"{ind}      X = {Convert.ToHexString(d, pos + 2, cl)}");
                    Console.WriteLine($"{ind}      Y = {Convert.ToHexString(d, pos + 2 + cl, cl)}");
                }
            }
            else if (tag == 0x04)
            {
                if (depth == 1)
                {
                    Console.WriteLine($"{ind}      (PKCS#8: chứa nguyên khối ECPrivateKey bên trong)");
                    Walk(d, pos, pos + len, depth + 1);
                }
                else
                {
                    Console.WriteLine($"{ind}      = {Convert.ToHexString(d, pos, len)}  (số bí mật d nếu là ECPrivateKey)");
                }
            }
            else if (tag == 0x05)
            {
                Console.WriteLine($"{ind}      NULL");
            }
            pos += len;
        }
    }
}

// ============================================================ mã hóa lai
static class Ecies
{
    static readonly byte[] Info = Encoding.UTF8.GetBytes("BaiTap-ECIES-v1");
    const string CipherFile = "ecc_cipher.b64";
    const string PlainFile = "ecc_plain.bin";

    // định dạng: len(2, big-endian) || SPKI khóa tạm || nonce(12) || bản mã || thẻ(16)
    public static byte[] Encrypt(ECDiffieHellman receiverPub, byte[] plain)
    {
        using var eph = ECDiffieHellman.Create(Helpers.CurveByBits(receiverPub.KeySize));
        byte[] secret = eph.DeriveRawSecretAgreement(receiverPub.PublicKey);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, null, Info);
        byte[] spki = eph.ExportSubjectPublicKeyInfo();
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ct = new byte[plain.Length];
        byte[] tag = new byte[16];
        using (var aead = new ChaCha20Poly1305(key))
            aead.Encrypt(nonce, plain, ct, tag);
        byte[] len = { (byte)(spki.Length >> 8), (byte)(spki.Length & 0xFF) };
        return Helpers.Concat(len, spki, nonce, ct, tag);
    }

    public static byte[] Decrypt(ECDiffieHellman receiverPriv, byte[] blob)
    {
        int spkiLen = (blob[0] << 8) | blob[1];
        byte[] spki = blob.AsSpan(2, spkiLen).ToArray();
        int off = 2 + spkiLen;
        byte[] nonce = blob.AsSpan(off, 12).ToArray();
        int ctLen = blob.Length - off - 12 - 16;
        byte[] ct = blob.AsSpan(off + 12, ctLen).ToArray();
        byte[] tag = blob.AsSpan(blob.Length - 16, 16).ToArray();

        using var ephPub = ECDiffieHellman.Create();
        ephPub.ImportSubjectPublicKeyInfo(spki, out _);
        byte[] secret = receiverPriv.DeriveRawSecretAgreement(ephPub.PublicKey);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, null, Info);
        byte[] plain = new byte[ctLen];
        using var aead = new ChaCha20Poly1305(key);
        aead.Decrypt(nonce, ct, tag, plain);
        return plain;
    }

    public static void EncryptMenu(Func<string, string, string> ask)
    {
        if (!ChaCha20Poly1305.IsSupported) { Console.WriteLine("Nền tảng không hỗ trợ ChaCha20-Poly1305."); return; }
        string pubPath = ask("File public key của người nhận [public.pem]: ", "public.pem");
        if (!File.Exists(pubPath)) { Console.WriteLine("Không thấy file."); return; }
        using var recv = ECDiffieHellman.Create();
        recv.ImportFromPem(File.ReadAllText(pubPath));

        Console.WriteLine("Dữ liệu cần mã hóa:  1) khóa ChaCha20 ngẫu nhiên 32 byte   2) văn bản   3) file");
        byte[] plain;
        switch (ask("Chọn [1]: ", "1"))
        {
            case "2":
                plain = Encoding.UTF8.GetBytes(ask("Nhập văn bản: ", "xin chao"));
                break;
            case "3":
            {
                string f = ask("Đường dẫn file: ", "");
                if (!File.Exists(f)) { Console.WriteLine("Không thấy file."); return; }
                plain = File.ReadAllBytes(f);
                break;
            }
            default:
                plain = RandomNumberGenerator.GetBytes(32);
                Console.WriteLine("Khóa ngẫu nhiên: " + Convert.ToHexString(plain));
                break;
        }

        var sw = Stopwatch.StartNew();
        byte[] blob = Encrypt(recv, plain);
        sw.Stop();
        File.WriteAllBytes(PlainFile, plain);
        File.WriteAllText(CipherFile, Convert.ToBase64String(blob));
        Console.WriteLine($"Đã mã hóa {plain.Length} byte -> {blob.Length} byte trong {sw.Elapsed.TotalMilliseconds:F2} ms.");
        Console.WriteLine($"  Phần khóa công khai tạm: {2 + ((blob[0] << 8) | blob[1])} byte; nonce 12 byte; thẻ 16 byte.");
        Console.WriteLine($"  Đã lưu {CipherFile} (base64) và {PlainFile} (bản gốc, để so sánh ở menu 6).");
        string b64 = Convert.ToBase64String(blob);
        Console.WriteLine("  Bản mã base64: " + (b64.Length > 140 ? b64[..140] + "..." : b64));
        Console.WriteLine("  Không có giới hạn 190 byte như RSA-OAEP: dữ liệu được mã hóa bằng ChaCha20, ECC chỉ dùng để thỏa thuận khóa.");
    }

    public static void DecryptMenu(Func<string, string, string> ask)
    {
        if (!ChaCha20Poly1305.IsSupported) { Console.WriteLine("Nền tảng không hỗ trợ ChaCha20-Poly1305."); return; }
        string privPath = ask("File private key [private.pem]: ", "private.pem");
        if (!File.Exists(privPath) || !File.Exists(CipherFile)) { Console.WriteLine($"Thiếu {privPath} hoặc {CipherFile} (hãy chạy menu 5 trước)."); return; }
        using var priv = ECDiffieHellman.Create();
        priv.ImportFromPem(File.ReadAllText(privPath));
        byte[] blob = Convert.FromBase64String(File.ReadAllText(CipherFile).Trim());
        byte[] plain;
        try { plain = Decrypt(priv, blob); }
        catch (CryptographicException)
        {
            Console.WriteLine("GIẢI MÃ THẤT BẠI: sai private key hoặc bản mã bị sửa.");
            return;
        }
        Console.WriteLine($"Giải mã được {plain.Length} byte.");
        if (File.Exists(PlainFile))
            Console.WriteLine(plain.AsSpan().SequenceEqual(File.ReadAllBytes(PlainFile)) ? "=> GIỐNG HỆT dữ liệu gốc." : "=> KHÁC dữ liệu gốc!");
        if (plain.Length <= 64) Console.WriteLine("  hex : " + Convert.ToHexString(plain));
    }
}

// ============================================================ đo tốc độ
static class Bench
{
    static double Ms(int iters, Action a)
    {
        a(); // khởi động
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iters; i++) a();
        sw.Stop();
        return sw.Elapsed.TotalMilliseconds / iters;
    }

    public static void Run(int iters)
    {
        byte[] data = RandomNumberGenerator.GetBytes(64);
        Console.WriteLine($"Mỗi phép thử lặp {iters} lần (RSA sinh khóa chỉ 3 lần). Đơn vị: ms/lần.");
        Console.WriteLine($"{"Thuật toán",-14}{"Sinh khóa",12}{"ECDH",12}{"Ký",12}{"Xác minh",12}");

        foreach (int bits in new[] { 256, 384, 521 })
        {
            var curve = Helpers.CurveByBits(bits);
            using var k = ECDsa.Create(curve);
            using var a = ECDiffieHellman.Create(curve);
            using var b = ECDiffieHellman.Create(curve);
            byte[] sig = k.SignData(data, HashAlgorithmName.SHA512);
            double gen = Ms(iters, () => { using var t = ECDsa.Create(curve); });
            double dh = Ms(iters, () => a.DeriveRawSecretAgreement(b.PublicKey));
            double sign = Ms(iters, () => k.SignData(data, HashAlgorithmName.SHA512));
            double ver = Ms(iters, () => k.VerifyData(data, sig, HashAlgorithmName.SHA512));
            Console.WriteLine($"{"ECC P-" + bits,-14}{gen,12:F4}{dh,12:F4}{sign,12:F4}{ver,12:F4}");
        }

        foreach (int bits in new[] { 2048, 3072 })
        {
            using var rsa = RSA.Create(bits);
            byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            double gen = Ms(3, () => { using var t = RSA.Create(bits); t.ExportParameters(false); }); // ExportParameters ép sinh khóa thật (RSA.Create là lazy)
            double sign = Ms(iters, () => rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
            double ver = Ms(iters, () => rsa.VerifyData(data, sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
            Console.WriteLine($"{"RSA " + bits,-14}{gen,12:F4}{"-",12}{sign,12:F4}{ver,12:F4}");
        }
        Console.WriteLine("Gợi ý nhận xét: ECC ký nhanh hơn RSA nhiều, nhưng xác minh ECC chậm hơn RSA (e nhỏ); khóa ECC ngắn hơn rất nhiều.");
    }
}

// ============================================================ SHA-512
static class Sha512Lab
{
    public static void Run()
    {
        Console.WriteLine("Nhập chuỗi để băm (Enter trống để chuyển sang thí nghiệm 10000 lần):");
        byte[]? prev = null;
        while (true)
        {
            Console.Write("> ");
            string? s = Console.ReadLine();
            if (string.IsNullOrEmpty(s)) break;
            byte[] h = SHA512.HashData(Encoding.UTF8.GetBytes(s));
            Console.WriteLine($"  SHA-512 = {Convert.ToHexString(h).ToLowerInvariant()}");
            if (prev == null) Console.WriteLine("  (chuỗi đầu tiên)");
            else
            {
                int diff = Helpers.BitDiff(prev, h);
                Console.WriteLine($"  Số bit khác chuỗi trước: {diff}/512 ({diff * 100.0 / 512:F1}%)");
            }
            prev = h;
        }

        const int Trials = 10000;
        long sum = 0;
        int min = int.MaxValue, max = 0;
        byte[] msg = new byte[64];
        for (int t = 0; t < Trials; t++)
        {
            RandomNumberGenerator.Fill(msg);
            byte[] h1 = SHA512.HashData(msg);
            int bit = RandomNumberGenerator.GetInt32(msg.Length * 8);
            msg[bit / 8] ^= (byte)(1 << (bit % 8));
            byte[] h2 = SHA512.HashData(msg);
            int diff = Helpers.BitDiff(h1, h2);
            sum += diff;
            min = Math.Min(min, diff);
            max = Math.Max(max, diff);
        }
        double avg = (double)sum / Trials;
        Console.WriteLine($"Thí nghiệm đổi đúng 1 bit, {Trials} lần: trung bình {avg:F2}/512 bit ({avg * 100 / 512:F2}%), nhỏ nhất {min}, lớn nhất {max}.");
        Console.WriteLine($"Giá trị kỳ vọng: 256/512 (50%). Lệch so với kỳ vọng: {avg - 256:F2} bit.");
    }
}

// ============================================================ chữ ký
static class Signatures
{
    public static void Run(ECDsa ecc, Func<string, string, string> ask)
    {
        byte[] data = Encoding.UTF8.GetBytes(ask("Dữ liệu cần ký [Nguyen Huu Doan]: ", "Nguyen Huu Doan"));
        byte[] tampered = (byte[])data.Clone();
        tampered[0] ^= 0x01;

        Console.WriteLine();
        Console.WriteLine($"(a) ECDSA NGẪU NHIÊN ({Helpers.CurveName(ecc.KeySize)}, SHA-512), ký 5 lần:");
        var set = new HashSet<string>();
        bool allOk = true;
        for (int i = 1; i <= 5; i++)
        {
            byte[] sig = ecc.SignData(data, HashAlgorithmName.SHA512);
            set.Add(Convert.ToBase64String(sig));
            allOk &= ecc.VerifyData(data, sig, HashAlgorithmName.SHA512);
            Console.WriteLine($"    lần {i}: {Convert.ToHexString(sig)[..32]}...");
        }
        Console.WriteLine($"    Số chữ ký khác nhau = {set.Count} / 5; cả 5 xác minh đúng = {allOk}");
        byte[] s0 = ecc.SignData(data, HashAlgorithmName.SHA512);
        Console.WriteLine($"    Sửa 1 bit dữ liệu rồi xác minh: {ecc.VerifyData(tampered, s0, HashAlgorithmName.SHA512)} (mong đợi False)");

        Console.WriteLine();
        Console.WriteLine("(b) ECDSA XÁC ĐỊNH theo RFC 6979 (P-256, SHA-512, tự cài đặt), ký 5 lần:");
        ECDsa? temp = null;
        ECDsa key = ecc;
        if (ecc.KeySize != 256)
        {
            Console.WriteLine("    Khóa hiện tại không phải P-256, dùng một khóa P-256 tạm để minh họa.");
            temp = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            key = temp;
        }
        BigInteger d = Helpers.Big(key.ExportParameters(true).D!);
        var set2 = new HashSet<string>();
        bool ok2 = true;
        for (int i = 1; i <= 5; i++)
        {
            byte[] sig = DetEcdsa.Sign(d, data);
            set2.Add(Convert.ToBase64String(sig));
            ok2 &= key.VerifyData(data, sig, HashAlgorithmName.SHA512); // .NET xác minh được chữ ký tự tính
            Console.WriteLine($"    lần {i}: {Convert.ToHexString(sig)[..32]}...");
        }
        byte[] ds = DetEcdsa.Sign(d, data);
        Console.WriteLine($"    Số chữ ký khác nhau = {set2.Count} / 5; cả 5 xác minh đúng (bằng ECDsa của .NET) = {ok2}");
        Console.WriteLine($"    Sửa 1 bit dữ liệu rồi xác minh: {key.VerifyData(tampered, ds, HashAlgorithmName.SHA512)} (mong đợi False)");
        temp?.Dispose();

        Console.WriteLine();
        Console.WriteLine("So sánh nhanh:");
        Console.WriteLine("  ECDSA ngẫu nhiên : mỗi lần một chữ ký; nếu nonce k lặp hoặc đoán được thì lộ khóa riêng d.");
        Console.WriteLine("  ECDSA RFC 6979   : k = HMAC-DRBG(d, hash) nên cùng dữ liệu luôn cùng chữ ký, không phụ thuộc bộ sinh ngẫu nhiên.");
        Console.WriteLine("  Ed25519          : nonce dẫn xuất từ băm(khóa riêng || thông điệp), xác định ngay từ thiết kế (BCL của .NET chưa có).");
    }
}

// Chữ ký ECDSA xác định (RFC 6979) cho P-256 + SHA-512, dùng BigInteger.
static class DetEcdsa
{
    static BigInteger H(string s) => BigInteger.Parse("0" + s, System.Globalization.NumberStyles.HexNumber);
    static readonly BigInteger P = H("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    static readonly BigInteger N = H("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    static readonly BigInteger A = P - 3;
    static readonly BigInteger Gx = H("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    static readonly BigInteger Gy = H("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

    sealed record Pt(BigInteger X, BigInteger Y);

    static BigInteger Mod(BigInteger v, BigInteger m)
    {
        var r = v % m;
        return r.Sign < 0 ? r + m : r;
    }

    static BigInteger Inv(BigInteger v, BigInteger m) => BigInteger.ModPow(Mod(v, m), m - 2, m);

    static Pt? Add(Pt? p, Pt? q)
    {
        if (p is null) return q;
        if (q is null) return p;
        BigInteger l;
        if (p.X == q.X)
        {
            if (Mod(p.Y + q.Y, P).IsZero) return null;
            l = Mod((3 * p.X * p.X + A) * Inv(2 * p.Y, P), P);
        }
        else
        {
            l = Mod((q.Y - p.Y) * Inv(q.X - p.X, P), P);
        }
        BigInteger x = Mod(l * l - p.X - q.X, P);
        return new Pt(x, Mod(l * (p.X - x) - p.Y, P));
    }

    static Pt? Mul(BigInteger k, Pt? p)
    {
        Pt? r = null;
        while (k > 0)
        {
            if (!k.IsEven) r = Add(r, p);
            p = Add(p, p);
            k >>= 1;
        }
        return r;
    }

    static BigInteger BitsToInt(byte[] bs)
    {
        var v = new BigInteger(bs, isUnsigned: true, isBigEndian: true);
        int blen = bs.Length * 8;
        return blen > 256 ? v >> (blen - 256) : v;
    }

    static byte[] Int2Octets(BigInteger v)
    {
        byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] o = new byte[32];
        raw.CopyTo(o, 32 - raw.Length);
        return o;
    }

    static byte[] Hmac(byte[] k, byte[] m) => HMACSHA512.HashData(k, m);

    static BigInteger GenK(BigInteger x, byte[] h1)
    {
        byte[] xo = Int2Octets(x);
        byte[] ho = Int2Octets(BitsToInt(h1) % N);
        byte[] v = Enumerable.Repeat((byte)1, 64).ToArray();
        byte[] k = new byte[64];
        k = Hmac(k, Helpers.Concat(v, new byte[] { 0 }, xo, ho)); v = Hmac(k, v);
        k = Hmac(k, Helpers.Concat(v, new byte[] { 1 }, xo, ho)); v = Hmac(k, v);
        while (true)
        {
            var t = new List<byte>();
            while (t.Count * 8 < 256)
            {
                v = Hmac(k, v);
                t.AddRange(v);
            }
            BigInteger cand = BitsToInt(t.ToArray());
            if (cand >= 1 && cand < N) return cand;
            k = Hmac(k, Helpers.Concat(v, new byte[] { 0 })); v = Hmac(k, v);
        }
    }

    // trả về r || s (mỗi số 32 byte), định dạng IEEE P1363 mà ECDsa của .NET xác minh được
    public static byte[] Sign(BigInteger d, byte[] data)
    {
        byte[] h1 = SHA512.HashData(data);
        while (true)
        {
            BigInteger k = GenK(d, h1);
            Pt? R = Mul(k, new Pt(Gx, Gy));
            BigInteger r = Mod(R!.X, N);
            BigInteger s = Mod(Inv(k, N) * (BitsToInt(h1) + r * d), N);
            if (r.IsZero || s.IsZero) continue; // hầu như không xảy ra
            return Helpers.Concat(Int2Octets(r), Int2Octets(s));
        }
    }
}
