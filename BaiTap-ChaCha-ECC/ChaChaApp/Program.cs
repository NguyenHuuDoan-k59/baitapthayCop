using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

if (!ChaCha20Poly1305.IsSupported)
{
    Console.WriteLine("Nền tảng này không hỗ trợ ChaCha20-Poly1305 (ChaCha20Poly1305.IsSupported = false).");
    return;
}

byte[]? key = null;
const string KeyFile = "chacha.key";

bool NeedKey()
{
    if (key != null) return true;
    Console.WriteLine("Chưa có khóa. Hãy chọn menu 1 (sinh khóa) hoặc menu 3 (nhập khóa) trước.");
    return false;
}

string AskPath(string prompt)
{
    Console.Write(prompt);
    return (Console.ReadLine() ?? "").Trim().Trim('"');
}

while (true)
{
    Console.WriteLine();
    Console.WriteLine("=== BÀI 1: ChaCha20-Poly1305 ===");
    Console.WriteLine("1. Sinh khóa 256 bit");
    Console.WriteLine("2. Lưu khóa ra file chacha.key (base64)");
    Console.WriteLine("3. Nhập khóa từ file");
    Console.WriteLine("4. Mã hóa / giải mã văn bản");
    Console.WriteLine("5. Mã hóa file theo khối 1 MB (-> <file>.enc)");
    Console.WriteLine("6. Giải mã file .enc (-> <file>.enc.dec)");
    Console.WriteLine("7. So sánh hai file theo từng byte");
    Console.WriteLine("8. Test file lớn, đo thời gian (ghi chacha_results.csv)");
    Console.WriteLine("9. Thử nghiệm chống giả mạo (sửa 1 bit, cắt bớt khối)");
    Console.WriteLine("0. Thoát");
    Console.Write("Chọn: ");

    string? choice = Console.ReadLine()?.Trim();
    try
    {
        switch (choice)
        {
            case "1":
                key = RandomNumberGenerator.GetBytes(32);
                Console.WriteLine($"Đã sinh khóa {key.Length * 8} bit: {Convert.ToBase64String(key)}");
                break;

            case "2":
                if (!NeedKey()) break;
                File.WriteAllText(KeyFile, Convert.ToBase64String(key!));
                Console.WriteLine($"Đã lưu {Path.GetFullPath(KeyFile)}");
                break;

            case "3":
            {
                if (!File.Exists(KeyFile)) { Console.WriteLine("Không thấy file chacha.key ở thư mục hiện tại."); break; }
                byte[] k = Convert.FromBase64String(File.ReadAllText(KeyFile).Trim());
                if (k.Length != 32) { Console.WriteLine($"Khóa phải dài đúng 32 byte, file này có {k.Length} byte."); break; }
                key = k;
                Console.WriteLine("Đã nhập khóa 256 bit.");
                break;
            }

            case "4":
            {
                if (!NeedKey()) break;
                Console.Write("Nhập văn bản: ");
                string text = Console.ReadLine() ?? "";
                byte[] blob = ChaChaOps.EncryptBytes(key!, Encoding.UTF8.GetBytes(text));
                Console.WriteLine("Bản mã (base64): " + Convert.ToBase64String(blob));
                Console.WriteLine($"  Độ dài: {blob.Length} byte = nonce 12 + bản mã {blob.Length - 28} + thẻ 16");
                Console.WriteLine($"  nonce (12 byte đầu)         : {Convert.ToHexString(blob.AsSpan(0, 12))}");
                Console.WriteLine($"  thẻ xác thực (16 byte cuối) : {Convert.ToHexString(blob.AsSpan(blob.Length - 16))}");
                string back = Encoding.UTF8.GetString(ChaChaOps.DecryptBytes(key!, blob));
                Console.WriteLine("Giải mã lại: " + back);
                Console.WriteLine(back == text ? "=> KHỚP với văn bản gốc." : "=> KHÔNG khớp!");
                break;
            }

            case "5":
            {
                if (!NeedKey()) break;
                string path = AskPath("Đường dẫn file cần mã hóa: ");
                if (!File.Exists(path)) { Console.WriteLine("Không thấy file."); break; }
                var sw = Stopwatch.StartNew();
                ChaChaOps.EncryptFile(key!, path, path + ".enc");
                sw.Stop();
                Console.WriteLine($"Đã tạo {path}.enc trong {sw.Elapsed.TotalSeconds:F3} s");
                break;
            }

            case "6":
            {
                if (!NeedKey()) break;
                string path = AskPath("Đường dẫn file .enc cần giải mã: ");
                if (!File.Exists(path)) { Console.WriteLine("Không thấy file."); break; }
                var sw = Stopwatch.StartNew();
                bool ok = ChaChaOps.DecryptFile(key!, path, path + ".dec", out string err);
                sw.Stop();
                if (ok) Console.WriteLine($"Đã tạo {path}.dec trong {sw.Elapsed.TotalSeconds:F3} s");
                else Console.WriteLine("GIẢI MÃ THẤT BẠI, không ghi file. Lý do: " + err);
                break;
            }

            case "7":
            {
                string a = AskPath("File thứ nhất: ");
                string b = AskPath("File thứ hai : ");
                if (!File.Exists(a) || !File.Exists(b)) { Console.WriteLine("Không thấy file."); break; }
                Console.WriteLine(ChaChaOps.CompareFiles(a, b, out string msg) ? "GIỐNG HỆT nhau theo từng byte. " + msg : "KHÁC nhau. " + msg);
                break;
            }

            case "8":
                if (!NeedKey()) break;
                RunBigFileTest(key!);
                break;

            case "9":
                if (!NeedKey()) break;
                RunTamperTest(key!);
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

static void RunBigFileTest(byte[] aesKey)
{
    Console.Write("Kích thước (MB), cách nhau dấu phẩy [mặc định 100,1000,3000]: ");
    string? line = Console.ReadLine()?.Trim();
    long[] sizes = string.IsNullOrEmpty(line)
        ? new long[] { 100, 1000, 3000 }
        : line.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(long.Parse).ToArray();

    var inv = CultureInfo.InvariantCulture;
    var csv = new StringBuilder("MB,enc_s,dec_s,enc_MBps,dec_MBps,identical\n");
    Console.WriteLine();
    Console.WriteLine($"{"MB",8} {"enc s",9} {"dec s",9} {"enc MB/s",10} {"dec MB/s",10} {"giống hệt",10}");

    foreach (long mb in sizes)
    {
        string plain = $"big_{mb}.bin", enc = plain + ".enc", dec = enc + ".dec";
        try
        {
            ChaChaOps.CreateRandomFile(plain, mb);

            var sw = Stopwatch.StartNew();
            ChaChaOps.EncryptFile(aesKey, plain, enc);
            double encS = sw.Elapsed.TotalSeconds;

            sw.Restart();
            bool okDec = ChaChaOps.DecryptFile(aesKey, enc, dec, out string err);
            double decS = sw.Elapsed.TotalSeconds;

            bool same = okDec && ChaChaOps.CompareFiles(plain, dec, out _);
            Console.WriteLine($"{mb,8} {encS,9:F2} {decS,9:F2} {mb / encS,10:F0} {mb / decS,10:F0} {same,10}");
            csv.AppendLine(string.Join(",", mb, encS.ToString("F3", inv), decS.ToString("F3", inv),
                (mb / encS).ToString("F1", inv), (mb / decS).ToString("F1", inv), same));
            if (!okDec) Console.WriteLine("  Lỗi giải mã: " + err);
        }
        finally
        {
            foreach (var f in new[] { plain, enc, dec }) if (File.Exists(f)) File.Delete(f);
        }
    }
    File.WriteAllText("chacha_results.csv", csv.ToString());
    Console.WriteLine("Đã ghi chacha_results.csv. Các file tạm đã được xóa.");
}

static void RunTamperTest(byte[] aesKey)
{
    // 1) văn bản: sửa 1 bit
    byte[] blob = ChaChaOps.EncryptBytes(aesKey, Encoding.UTF8.GetBytes("Thong diep can bao ve"));
    Console.WriteLine("Thử 1: sửa 1 bit của bản mã văn bản rồi giải mã");
    blob[14] ^= 0x01;
    try { ChaChaOps.DecryptBytes(aesKey, blob); Console.WriteLine("  => GIẢI MÃ ĐƯỢC (không mong đợi!)"); }
    catch (CryptographicException) { Console.WriteLine("  => Bị từ chối: thẻ xác thực không khớp (đúng mong đợi)."); }

    // 2) file nhiều khối
    string plain = "tamper_test.bin", enc = plain + ".enc", dec = enc + ".dec";
    try
    {
        ChaChaOps.CreateRandomFile(plain, 3); // 3 MB = 3 khối
        ChaChaOps.EncryptFile(aesKey, plain, enc);
        byte[] good = File.ReadAllBytes(enc);

        Console.WriteLine("Thử 2: sửa 1 bit ở giữa file .enc");
        byte[] t1 = (byte[])good.Clone();
        t1[t1.Length / 2] ^= 0x01;
        File.WriteAllBytes(enc, t1);
        bool ok = ChaChaOps.DecryptFile(aesKey, enc, dec, out string err);
        Console.WriteLine($"  => thành công = {ok}, file .dec tồn tại = {File.Exists(dec)}; lý do: {err}");

        Console.WriteLine("Thử 3: cắt bỏ khối cuối (kẻ tấn công xóa bớt dữ liệu)");
        int recordSize = 4 + ChaChaOps.ChunkSize + 16;
        byte[] t2 = good.AsSpan(0, ChaChaOps.HeaderSize + 2 * recordSize).ToArray();
        File.WriteAllBytes(enc, t2);
        ok = ChaChaOps.DecryptFile(aesKey, enc, dec, out err);
        Console.WriteLine($"  => thành công = {ok}, file .dec tồn tại = {File.Exists(dec)}; lý do: {err}");
        Console.WriteLine("     (nhờ cờ 'khối cuối' trong AAD nên khối 2 không thể bị coi là khối cuối)");

        Console.WriteLine("Thử 4: hoán đổi khối 1 và khối 2");
        byte[] t3 = (byte[])good.Clone();
        Buffer.BlockCopy(good, ChaChaOps.HeaderSize + recordSize, t3, ChaChaOps.HeaderSize, recordSize);
        Buffer.BlockCopy(good, ChaChaOps.HeaderSize, t3, ChaChaOps.HeaderSize + recordSize, recordSize);
        File.WriteAllBytes(enc, t3);
        ok = ChaChaOps.DecryptFile(aesKey, enc, dec, out err);
        Console.WriteLine($"  => thành công = {ok}, file .dec tồn tại = {File.Exists(dec)}; lý do: {err}");
        Console.WriteLine("     (nhờ chỉ số khối trong nonce và AAD)");
    }
    finally
    {
        foreach (var f in new[] { plain, enc, dec }) if (File.Exists(f)) File.Delete(f);
    }
}

static class ChaChaOps
{
    public const int ChunkSize = 1 << 20;   // 1 MB
    public const int TagSize = 16;
    public const int NonceSize = 12;
    public const int HeaderSize = 8;         // "CCP1" + tiền tố nonce 4 byte
    static readonly byte[] Magic = "CCP1"u8.ToArray();

    // ---- văn bản: nonce(12) || bản mã || thẻ(16) ----
    public static byte[] EncryptBytes(byte[] key, byte[] plain)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] result = new byte[NonceSize + plain.Length + TagSize];
        nonce.CopyTo(result, 0);
        using var aead = new ChaCha20Poly1305(key);
        aead.Encrypt(nonce,
            plain,
            result.AsSpan(NonceSize, plain.Length),
            result.AsSpan(NonceSize + plain.Length, TagSize));
        return result;
    }

    public static byte[] DecryptBytes(byte[] key, byte[] blob)
    {
        if (blob.Length < NonceSize + TagSize) throw new CryptographicException("Dữ liệu quá ngắn.");
        int ctLen = blob.Length - NonceSize - TagSize;
        byte[] plain = new byte[ctLen];
        using var aead = new ChaCha20Poly1305(key);
        aead.Decrypt(blob.AsSpan(0, NonceSize),
            blob.AsSpan(NonceSize, ctLen),
            blob.AsSpan(NonceSize + ctLen, TagSize),
            plain);
        return plain;
    }

    // ---- file: "CCP1" || tiền tố(4) || { độ dài(4) || bản mã || thẻ(16) } ... ----
    static void MakeNonce(byte[] prefix, long index, byte[] nonce)
    {
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(4), index);
    }

    static void MakeAad(long index, bool isLast, byte[] aad)
    {
        BinaryPrimitives.WriteInt64BigEndian(aad, index);
        aad[8] = (byte)(isLast ? 1 : 0);
    }

    public static void EncryptFile(byte[] key, string inPath, string outPath)
    {
        using var input = File.OpenRead(inPath);
        using var output = File.Create(outPath);
        long total = input.Length;
        long count = Math.Max(1, (total + ChunkSize - 1) / ChunkSize);
        byte[] prefix = RandomNumberGenerator.GetBytes(4);

        output.Write(Magic);
        output.Write(prefix);

        using var aead = new ChaCha20Poly1305(key);
        byte[] plain = new byte[ChunkSize], cipher = new byte[ChunkSize];
        byte[] tag = new byte[TagSize], nonce = new byte[NonceSize], aad = new byte[9];

        for (long i = 0; i < count; i++)
        {
            int n = (int)Math.Min(ChunkSize, total - i * ChunkSize);
            input.ReadExactly(plain, 0, n);
            MakeNonce(prefix, i, nonce);
            MakeAad(i, i == count - 1, aad);
            aead.Encrypt(nonce, plain.AsSpan(0, n), cipher.AsSpan(0, n), tag, aad);
            output.Write(BitConverter.GetBytes(n));
            output.Write(cipher, 0, n);
            output.Write(tag);
        }
    }

    public static bool DecryptFile(byte[] key, string inPath, string outPath, out string error)
    {
        error = "";
        string tmp = outPath + ".tmp";
        try
        {
            using (var input = File.OpenRead(inPath))
            using (var output = File.Create(tmp))
            {
                byte[] header = new byte[HeaderSize];
                input.ReadExactly(header, 0, HeaderSize);
                if (!header.AsSpan(0, 4).SequenceEqual(Magic))
                {
                    error = "Không phải file .enc của chương trình này (sai chữ ký đầu file).";
                    return false;
                }
                byte[] prefix = header.AsSpan(4, 4).ToArray();

                using var aead = new ChaCha20Poly1305(key);
                byte[] plain = new byte[ChunkSize], cipher = new byte[ChunkSize];
                byte[] tag = new byte[TagSize], nonce = new byte[NonceSize], aad = new byte[9];
                byte[] lenBuf = new byte[4];
                long i = 0;

                while (input.Position < input.Length)
                {
                    input.ReadExactly(lenBuf, 0, 4);
                    int n = BitConverter.ToInt32(lenBuf, 0);
                    if (n < 0 || n > ChunkSize) { error = "Độ dài khối không hợp lệ (file hỏng)."; return false; }
                    input.ReadExactly(cipher, 0, n);
                    input.ReadExactly(tag, 0, TagSize);
                    bool isLast = input.Position == input.Length;
                    MakeNonce(prefix, i, nonce);
                    MakeAad(i, isLast, aad);
                    aead.Decrypt(nonce, cipher.AsSpan(0, n), tag, plain.AsSpan(0, n), aad);
                    output.Write(plain, 0, n);
                    i++;
                }
                if (i == 0) { error = "File không có khối dữ liệu nào."; return false; }
            }
            File.Move(tmp, outPath, true);
            return true;
        }
        catch (CryptographicException)
        {
            error = "thẻ xác thực không khớp (dữ liệu bị sửa, bị cắt/hoán đổi khối, hoặc sai khóa).";
            return false;
        }
        catch (EndOfStreamException)
        {
            error = "file bị cắt cụt hoặc hỏng.";
            return false;
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    public static bool CompareFiles(string a, string b, out string message)
    {
        using var fa = File.OpenRead(a);
        using var fb = File.OpenRead(b);
        if (fa.Length != fb.Length)
        {
            message = $"Độ dài khác nhau: {fa.Length} và {fb.Length} byte.";
            return false;
        }
        byte[] ba = new byte[ChunkSize], bb = new byte[ChunkSize];
        long pos = 0;
        while (pos < fa.Length)
        {
            int n = (int)Math.Min(ChunkSize, fa.Length - pos);
            fa.ReadExactly(ba, 0, n);
            fb.ReadExactly(bb, 0, n);
            if (!ba.AsSpan(0, n).SequenceEqual(bb.AsSpan(0, n)))
            {
                int idx = ba.AsSpan(0, n).CommonPrefixLength(bb.AsSpan(0, n));
                message = $"Byte khác đầu tiên ở vị trí {pos + idx}.";
                return false;
            }
            pos += n;
        }
        message = $"({fa.Length} byte)";
        return true;
    }

    public static void CreateRandomFile(string path, long megabytes)
    {
        using var fs = File.Create(path);
        byte[] buf = new byte[ChunkSize];
        for (long i = 0; i < megabytes; i++)
        {
            RandomNumberGenerator.Fill(buf);
            fs.Write(buf, 0, buf.Length);
        }
    }
}
