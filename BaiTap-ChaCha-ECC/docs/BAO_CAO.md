# Báo cáo: ChaCha20-Poly1305, ECC, SHA-512, ECDSA

**Sinh viên:** Nguyen Huu Doan – K59KMT – Trường ĐH Kỹ thuật Công nghiệp Thái Nguyên
**Máy đo:** Windows, `cmd.exe` · CPU: `<điền>` · .NET: `<điền>` · ngày đo: 26/10/2026

Quy ước nguồn số liệu: **[ảnh]** = đọc từ ảnh chụp app C# trong `docs/images/`; **[Python]** = từ `reference/ket_qua_tham_chieu.txt` (máy khác, chỉ tham chiếu); **[tính]** = suy ra từ số [ảnh]; **[file]** = đo từ file khóa mẫu cùng định dạng.

## 1. Thiết kế (yêu cầu → cách làm)

| Yêu cầu | Cách làm |
|---|---|
| AEAD cho văn bản | `nonce(12) ‖ bản mã ‖ thẻ(16)`, base64 |
| File lớn không tràn RAM | Chia khối 1 MB, đọc/ghi từng khối; nonce = tiền tố 4 byte ‖ bộ đếm 64 bit |
| Chống hoán đổi, xóa, cắt khối | AAD = chỉ số khối ‖ cờ «khối cuối» |
| Không ghi dữ liệu sai | Giải mã ra file tạm, chỉ đổi tên nếu mọi thẻ đúng |
| Khóa ECC, PEM | `ECDsa`/`ECDiffieHellman` của .NET; SPKI và PKCS#8 |
| Mã hóa lai | Khóa tạm ECDH → HKDF-SHA256 → ChaCha20-Poly1305 |
| Chữ ký xác định | RFC 6979 tự cài (P-256, SHA-512), kiểm tra bằng vector chính thức |

## 2. Bài 1: kết quả

| Menu | Kết quả [ảnh] | Ảnh |
|---|---|---|
| 1, 2, 3 | Sinh, lưu, nhập khóa 256 bit thành công | `bai1_menu1-3_khoa.jpg` |
| 4 | 15 byte → 43 byte (12 + 15 + 16); giải mã khớp | `bai1_menu4-5_...jpg` |
| 5 | `test.txt` → `.enc` trong 0.002 s | `bai1_menu4-5_...jpg` |
| 6 | `.enc` → `.enc.dec` trong 0.004 s | `bai1_menu6-7_...jpg` |
| 7 | `test.txt` (16 byte) khác `test.txt.enc` (44 byte) | `bai1_menu6-7_...jpg` |
| 8 | **Chưa có ảnh** – cần chạy và điền bảng dưới | – |
| 9 | **Chưa có ảnh** – cần chạy và ghi kết quả 3 thử nghiệm | – |

Bảng menu 8 (điền sau khi chạy, lấy từ `chacha_results.csv` và ảnh):

| Kích thước | Mã hóa (s) | Giải mã (s) | MB/s mã hóa | MB/s giải mã | Giống bản gốc |
|---:|---:|---:|---:|---:|---|
| 100 MB | | | | | |
| 1000 MB | | | | | |
| 3000 MB | | | | | |

### Câu hỏi phân tích

1. **Dùng lại (khóa, nonce).** ChaCha20 là mã dòng: bản mã = bản rõ ⊕ keystream. Hai thông điệp cùng (khóa, nonce) dùng cùng keystream, nên C₁ ⊕ C₂ = P₁ ⊕ P₂, kẻ tấn công khử keystream và suy ra bản rõ (nhất là khi đoán được một trong hai). Ngoài ra khóa một lần của Poly1305 sinh từ (khóa, nonce) nên cũng bị lặp, cho phép giả mạo thẻ xác thực.
2. **AAD chỉ số khối và cờ khối cuối.** Mỗi khối tự xác thực được, nên nếu không gắn vị trí vào AAD, kẻ tấn công có thể hoán đổi, lặp hoặc xóa khối, hoặc cắt bớt các khối cuối mà mọi thẻ vẫn đúng. Gắn chỉ số khối chặn hoán đổi/lặp/xóa giữa chừng; cờ «khối cuối» chặn việc cắt đuôi.
3. **Tuyến tính theo kích thước.** Mã hóa theo khối 1 MB độc lập nên thời gian tăng gần tuyến tính. [Python, máy khác] 100 MB: 0.04 s (2409 MB/s), 1000 MB: 0.41 s (2448 MB/s), tốc độ gần như không đổi. Số trên máy của em cần điền từ menu 8.
4. **So với AES-CBC.** (i) Chống sửa đổi: CBC không có xác thực, phải ghép thêm HMAC và dễ sai (padding oracle, đảo bit); ChaCha20-Poly1305 có thẻ xác thực sẵn. (ii) Song song: CBC mã hóa tuần tự (giải mã song song được); ChaCha20 tính từng khối độc lập nên song song cả hai chiều. (iii) Máy không có AES-NI: AES phần mềm chậm và dễ lộ qua kênh phụ (bảng tra); ChaCha20 chỉ dùng cộng, xoay, XOR nên nhanh và ổn định.
5. **Bộ nhớ hằng số.** App chỉ giữ một khối 1 MB (cùng bộ đệm tương ứng) tại mỗi thời điểm, đọc khối → mã hóa → ghi ngay; dung lượng file không ảnh hưởng RAM.

## 3. Bài 2: kết quả

### 3.1 PEM (menu 1 đến 4)

| Mục | Giá trị |
|---|---|
| Đường cong | nistP256 (prime256v1), 256 bit [ảnh] |
| DER `public.pem` | **91 byte**, base64 **124 ký tự** [ảnh] |
| DER `private.pem` (PKCS#8, P-256) | **138 byte**, base64 **184 ký tự** [file] |
| Qx (256 bit) | `DA217BCF...662D489C4` [ảnh] |
| Qy (253 bit) | `19C26D2D...E84C42E7E` [ảnh] |
| Q thuộc đường cong | ĐÚNG [ảnh] |

Điền bảng ý nghĩa byte của đề: `30` SEQUENCE; `06 07 2A 86 48 CE 3D 02 01` OID id-ecPublicKey; `06 08 2A 86 48 CE 3D 03 01 07` OID P-256; `03` BIT STRING chứa điểm; `04` đầu điểm = không nén `04 ‖ X ‖ Y` (65 byte với P-256); `04` (OCTET STRING) trong PKCS#8 chứa ECPrivateKey (có d).

- **(a)** Public: 91 byte / 124 ký tự base64; private: 138 byte / 184 ký tự base64 (4 ký tự base64 = 3 byte, có đệm `=`).
- **(b)** Đổi đường cong thì đổi OID tên đường cong (thành 1.3.132.0.34 hoặc 1.3.132.0.35), độ dài điểm công khai (97 byte với P-384, 133 byte với P-521) và các trường độ dài bao ngoài; OID id-ecPublicKey giữ nguyên.
- **(c)** Bài toán logarit rời rạc trên đường cong elliptic khó hơn nhiều so với phân tích số nguyên, nên ECC 256 bit (khoảng 128 bit an toàn) tương đương RSA 3072 bit. Khóa công khai ECC chỉ là một điểm 65 byte, còn RSA 3072 có modulus 384 byte.

### 3.2 Mã hóa lai (menu 5, 6)

[ảnh] 32 byte → 153 byte trong 11.31 ms = 93 (khóa tạm: 2 byte độ dài + 91 byte SPKI) + 12 (nonce) + 32 + 16 (thẻ); giải mã bằng `private.pem` khớp 32 byte gốc. **Chưa có ảnh** cho văn bản 1 KB và file 5 MB.

- **(a)** ECC không mã hóa trực tiếp dữ liệu; nó chỉ thỏa thuận khóa. Dữ liệu được mã hóa bằng ChaCha20-Poly1305 nên không bị giới hạn như RSA-OAEP (190 byte với khóa 2048 bit, SHA-256).
- **(b)** Khóa tạm mới mỗi lần cho khóa phiên mới và nonce an toàn theo từng thông điệp, và nếu lộ khóa riêng dài hạn thì các thông điệp cũ không bị giải mã (bảo mật chuyển tiếp với phía gửi).
- **(c)** Bí mật chung ECDH là một tọa độ điểm, không phân phối đều và dài tùy đường cong. HKDF trích xuất độ ngẫu nhiên, tạo đúng 32 byte và gắn ngữ cảnh (`info`) để khóa dùng cho đúng mục đích.

### 3.3 Đo tốc độ (menu 7) [ảnh], ms/lần, lặp 200 lần

| Thuật toán | Sinh khóa | ECDH | Ký | Xác minh |
|---|---:|---:|---:|---:|
| ECC P-256 | 1.0303 | 0.8259 | 0.2699 | 0.2548 |
| ECC P-384 | 1.9730 | 1.2316 | 0.5605 | 0.5874 |
| ECC P-521 | 4.4861 | 2.0361 | 1.3910 | 1.5125 |
| RSA 2048 | không hợp lệ (*) | – | 0.4934 | 0.0170 |
| RSA 3072 | không hợp lệ (*) | – | 1.5808 | 0.0323 |

(*) Số 0.0007 và 0.0001 trong ảnh là do lỗi đo (`RSA.Create` sinh khóa lười), đã sửa trong mã; cần chạy lại menu 7.

- **Ký hay xác minh nhanh hơn?** Với ECC, hai phép gần bằng nhau (P-256 xác minh nhanh hơn chút: 0.2548 so với 0.2699; P-384 và P-521 thì ký nhanh hơn chút). Với RSA thì ngược hẳn: xác minh nhanh hơn ký rất nhiều (RSA 2048: 0.0170 so với 0.4934, khoảng 29 lần; RSA 3072: khoảng 49 lần) vì số mũ công khai e nhỏ.
- **P-256 → P-521** [tính]: sinh khóa ×4.35, ECDH ×2.47, ký ×5.15, xác minh ×5.94.
- **Ký ECC so với RSA** [tính]: P-256 ký nhanh hơn RSA 2048 khoảng 1.8 lần và RSA 3072 khoảng 5.9 lần; nhưng xác minh P-256 chậm hơn RSA 2048 khoảng 15 lần và RSA 3072 khoảng 7.9 lần.
- **Chọn gì cho thiết bị hạn chế?** Ở mức an toàn khoảng 128 bit (P-256 so với RSA 3072), nên chọn ECC: ký nhanh hơn gần 6 lần, khóa và chữ ký ngắn (tiết kiệm RAM, băng thông, bộ nhớ). RSA chỉ có lợi khi thiết bị chủ yếu **xác minh** rất nhiều chữ ký (xác minh RSA nhanh hơn) và ít khi ký.

### 3.4 SHA-512 và thác đổ (menu 8) [ảnh]

| Chuỗi nhập | SHA-512 (16 hex đầu) | Số bit khác chuỗi trước |
|---|---|---|
| `DOAN DOAN DOAN` | `b8091a630c0c8a1b` | – |
| `doan doan doAn` | `c647a14d3a86e807` | 253/512 (49.4%) |
| `DoAN Doan DOa` | `dede9df649552063` | 263/512 (51.4%) |

Đổi đúng 1 bit, 10000 lần: trung bình **256.03/512** (50.01%), nhỏ nhất 214, lớn nhất 309.

- **(a)** Kỳ vọng 256 bit (50%); kết quả lệch **0.03 bit**. [Python, máy khác] cho 256.10, min 214, max 304, cũng sát 256.
- **(b)** Chữ ký số ký trên giá trị băm; chỉ cần đổi 1 bit của thông điệp thì băm đổi khoảng một nửa số bit, chữ ký cũ không còn khớp. Nhờ vậy không thể sửa nhẹ nội dung mà giữ nguyên chữ ký, đồng thời không thể suy ngược ra thông điệp từ băm.
- **(c)** SHA-512 là hàm tất định (không có yếu tố ngẫu nhiên): cùng đầu vào cho cùng đầu ra, nên 0 bit khác. (Chưa có ảnh dòng nhập lại y hệt chuỗi trước.)

### 3.5 ECDSA (menu 9) [ảnh]

| Cách ký | Các lần ký có giống nhau? | Rủi ro khi bộ sinh ngẫu nhiên kém | Chuẩn hóa |
|---|---|---|---|
| ECDSA ngẫu nhiên | Không: 5/5 chữ ký khác nhau | Nonce k lặp hoặc đoán được thì lộ khóa riêng d | FIPS 186, ANSI X9.62 |
| ECDSA xác định (RFC 6979) | Có: 1/5 chữ ký duy nhất, cả 5 xác minh đúng | k = HMAC-DRBG(d, h) nên không phụ thuộc bộ sinh ngẫu nhiên khi ký | RFC 6979 |
| Ed25519 | Có (xác định từ thiết kế) | Nonce = băm(phần khóa riêng ‖ thông điệp), không cần ngẫu nhiên khi ký | RFC 8032 (.NET chưa hỗ trợ sẵn) |

- **(a)** 5 chữ ký ngẫu nhiên đều khác nhau và cả 5 xác minh đúng; sửa 1 bit dữ liệu thì xác minh trả `False` như mong đợi. Với RFC 6979 cả 5 lần ra cùng chữ ký `4789A99B...`, xác minh đúng bằng `ECDsa` của .NET, sửa 1 bit thì `False`.
- **(b)** Mỗi lần ký chọn k ngẫu nhiên mới nên r = x(k·G) mod n và s = k⁻¹(h + r·d) mod n đều đổi. Đây là bình thường: mỗi cặp (r, s) đều thỏa phương trình xác minh; độ an toàn nằm ở việc k **bí mật và không lặp**, không nằm ở việc chữ ký giống nhau.
- **(c)** Chứng minh khi hai chữ ký cùng nonce k (cùng r): s₁ = k⁻¹(h₁ + r·d), s₂ = k⁻¹(h₂ + r·d). Trừ hai vế: s₁ − s₂ = k⁻¹(h₁ − h₂), suy ra **k = (h₁ − h₂)(s₁ − s₂)⁻¹ mod n**. Thay k vào s₁·k = h₁ + r·d, suy ra **d = (s₁·k − h₁)·r⁻¹ mod n**. Vậy chỉ cần hai chữ ký trùng nonce là lộ khóa riêng; hậu quả thực tế khi bộ sinh số ngẫu nhiên kém hoặc k bị lặp (khóa riêng bị lộ và kẻ tấn công ký giả mạo được).
- **(d)** Đề xuất dùng ECDSA xác định theo RFC 6979: k được dẫn xuất bằng HMAC-DRBG từ khóa riêng d và giá trị băm h, nên cùng (d, h) cho cùng k, còn khác thông điệp (khác h) thì k khác một cách không đoán được. Không cần bộ sinh ngẫu nhiên khi ký, nên loại bỏ rủi ro nonce lặp do RNG kém. App cài đặt phương án này (P-256, SHA-512) và đã kiểm tra bằng vector chính thức của RFC 6979.

## 4. Kết luận và hạn chế

- Cả hai app chạy đúng các menu đã có ảnh minh chứng; số liệu trong báo cáo lấy từ ảnh chụp app C# trên máy sinh viên.
- **Còn thiếu minh chứng:** Bài 1 menu 8 và 9; mã hóa lai với văn bản 1 KB và file 5 MB; dòng «nhập lại y hệt → 0/512» của menu 8 Bài 2; ảnh `private.pem` (menu 3, 4 với khóa riêng, hiện d).
- **Cần đo lại:** ô sinh khóa RSA của menu 7 (lỗi đã sửa trong mã).
- RFC 6979 chỉ cài cho P-256; Ed25519 chỉ nêu trong lý thuyết vì .NET chưa hỗ trợ sẵn.
