# Bài tập An toàn và Bảo mật thông tin: ChaCha20-Poly1305, ECC, SHA-512, chữ ký ECDSA

*Đề bài tương tự bài tập AES - RSA - SHA-256 - chữ ký số, đã đổi các từ khóa: AES-CBC → ChaCha20-Poly1305, RSA → ECC (ECDH, ECDSA), SHA-256 → SHA-512, PKCS#1 v1.5 / RSA-PSS → ECDSA ngẫu nhiên / ECDSA xác định.*

## 1. Mục tiêu

- Cài đặt mã hóa đối xứng **có xác thực** (AEAD) với ChaCha20-Poly1305 cho văn bản và file lớn hàng GB.
- Thao tác với khóa **đường cong elliptic (ECC)**: sinh khóa, xuất/nhập PEM, đọc cấu trúc ASN.1/DER.
- Xây dựng sơ đồ **mã hóa lai** (ECDH + HKDF + ChaCha20-Poly1305) thay cho mã hóa trực tiếp bằng khóa công khai.
- Quan sát **hiệu ứng thác đổ** của SHA-512 bằng thực nghiệm.
- Phân tích tính ngẫu nhiên của chữ ký ECDSA và đề xuất cách làm chữ ký **xác định** (RFC 6979).

## 2. Yêu cầu chung

| Hạng mục | Quy định |
|---|---|
| Ngôn ngữ | C# (.NET 8 trở lên), ứng dụng console có menu số |
| Thư viện | Chỉ dùng `System.Security.Cryptography`, không tự cài đặt thuật toán mật mã cơ bản |
| Cấu trúc | Hai dự án: `ChaChaApp` (Bài 1) và `EccApp` (Bài 2) |
| Ký tự | Đặt `Console.InputEncoding` và `Console.OutputEncoding` là UTF-8 |
| Khóa bí mật | Không đưa `chacha.key`, `private.pem` lên GitHub; ghi vào `.gitignore` |
| Số liệu | Mọi số liệu trong báo cáo phải đo bằng app chạy trên máy của chính sinh viên, có ảnh chụp minh chứng |

> Lưu ý: `ChaCha20Poly1305` của .NET chỉ chạy khi `ChaCha20Poly1305.IsSupported` là `true`. Hãy kiểm tra và in thông báo rõ ràng nếu nền tảng không hỗ trợ.

## 3. Bài 1. ChaCha20-Poly1305 (mã hóa đối xứng có xác thực)

### 3.1 Chức năng cần có

| Menu | Chức năng |
|---|---|
| 1 | Sinh khóa ngẫu nhiên 256 bit (32 byte) bằng `RandomNumberGenerator` |
| 2 | Lưu khóa ra file `chacha.key` dạng base64 |
| 3 | Nhập khóa từ file, kiểm tra độ dài đúng 32 byte |
| 4 | Mã hóa một đoạn văn bản nhập từ bàn phím: in bản mã base64, giải mã lại để đối chiếu |
| 5 | Mã hóa file bất kỳ, ghi ra `<tên file>.enc` |
| 6 | Giải mã file `.enc`, ghi ra `<tên file>.enc.dec` |
| 7 | So sánh hai file theo từng byte, báo vị trí byte khác đầu tiên (nếu có) |
| 8 | Tự tạo file ngẫu nhiên 100 MB, 1 GB, 3 GB; mã hóa, giải mã, so sánh; in bảng thời gian và tốc độ; ghi `chacha_results.csv` |
| 9 | Thử nghiệm chống giả mạo: sửa 1 bit của bản mã rồi giải mã, ghi nhận kết quả |

### 3.2 Quy định về định dạng dữ liệu

- **Văn bản:** `nonce (12 byte, ngẫu nhiên) ‖ bản mã ‖ thẻ xác thực (16 byte)`, sau đó mã hóa base64.
- **File lớn:** chia thành các khối 1 MB, xử lý theo dòng (không đọc cả file vào RAM). Mỗi khối được mã hóa độc lập, nonce của khối thứ *i* gồm tiền tố ngẫu nhiên 4 byte của file ghép với bộ đếm 64 bit *i*. Tiền tố ghi ở đầu file `.enc`.
- **Dữ liệu xác thực kèm theo (AAD):** gồm chỉ số khối và cờ «khối cuối cùng», để kẻ tấn công không thể hoán đổi, xóa hoặc cắt bớt các khối mà không bị phát hiện.
- Khi thẻ xác thực sai, chương trình phải báo lỗi và **không ghi** dữ liệu giải mã ra file.

### 3.3 Câu hỏi phân tích (ghi vào báo cáo)

1. Vì sao không bao giờ được dùng lại cùng một cặp (khóa, nonce) cho hai thông điệp khác nhau? Điều gì xảy ra với bản rõ nếu vi phạm?
2. Vì sao cần AAD chứa chỉ số khối và cờ khối cuối? Nếu bỏ đi thì kẻ tấn công làm được gì?
3. Thời gian mã hóa có tăng tuyến tính theo kích thước file không? Tính tốc độ MB/s và nhận xét.
4. So sánh ChaCha20-Poly1305 với AES-CBC về: khả năng chống sửa đổi, khả năng xử lý song song, và hiệu năng trên máy không có lệnh AES-NI.
5. Bộ nhớ chương trình dùng gần như hằng số bất kể file lớn bao nhiêu. Giải thích nguyên nhân.

## 4. Bài 2. ECC, SHA-512 và chữ ký số ECDSA

### 4.1 Chức năng cần có

| Menu | Chức năng |
|---|---|
| 1 | Sinh cặp khóa ECC trên đường cong **nistP256**, **nistP384** hoặc **nistP521** (người dùng chọn) |
| 2 | Xuất `public.pem` (X.509 SPKI, `BEGIN PUBLIC KEY`) và `private.pem` (PKCS#8, `BEGIN PRIVATE KEY`) |
| 3 | Xem PEM: giải base64 ra DER, in cây ASN.1 kèm offset, byte Tag/Length và nhãn từng trường |
| 4 | Nhập PEM: public key hiện tên đường cong, Qx, Qy; private key hiện thêm số bí mật d. Kiểm tra điểm Q nằm trên đường cong |
| 5 | Mã hóa lai bằng public key (ECDH + HKDF + ChaCha20-Poly1305), lưu base64 |
| 6 | Giải mã bằng private key, so sánh với dữ liệu gốc |
| 7 | Đo tốc độ: sinh khóa, ECDH, ký, xác minh theo từng đường cong |
| 8 | SHA-512 và hiệu ứng thác đổ |
| 9 | Chữ ký số ECDSA: ngẫu nhiên và xác định |

### 4.2 Xem và nhập PEM (menu 3, 4)

Giải thích ý nghĩa các byte trong DER và điền bảng sau cho khóa P-256 của mình:

| Byte / giá trị | Ý nghĩa cần giải thích |
|---|---|
| `30` | SEQUENCE |
| `06 07 2A 86 48 CE 3D 02 01` | OID 1.2.840.10045.2.1 (id-ecPublicKey) |
| `06 08 2A 86 48 CE 3D 03 01 07` | OID 1.2.840.10045.3.1.7 (đường cong prime256v1 / P-256) |
| `03` | BIT STRING chứa điểm công khai |
| `04` đầu điểm | Điểm **không nén**: `04 ‖ X ‖ Y`, tổng 65 byte với P-256 |
| `04` (OCTET STRING) | Trong PKCS#8, chứa cấu trúc ECPrivateKey (có số bí mật d) |

Câu hỏi: (a) Độ dài DER của `public.pem` và `private.pem` là bao nhiêu byte, ứng với bao nhiêu ký tự base64? (b) Với OID của P-384 là 1.3.132.0.34 và P-521 là 1.3.132.0.35, phần nào của file thay đổi khi đổi đường cong? (c) Vì sao khóa công khai ECC ngắn hơn nhiều so với RSA ở cùng mức an toàn?

### 4.3 Mã hóa lai ECDH + ChaCha20-Poly1305 (menu 5, 6)

ECC không mã hóa trực tiếp dữ liệu như RSA-OAEP, nên cần sơ đồ lai kiểu ECIES:

1. Người gửi sinh cặp khóa **tạm** (ephemeral) trên cùng đường cong với khóa công khai của người nhận.
2. Tính bí mật chung bằng ECDH giữa khóa riêng tạm và khóa công khai người nhận.
3. Dẫn xuất khóa 32 byte bằng **HKDF-SHA256** từ bí mật chung (dùng chuỗi ngữ cảnh cố định làm `info`).
4. Mã hóa dữ liệu bằng ChaCha20-Poly1305 (tái sử dụng mã của Bài 1).
5. Đầu ra: `khóa công khai tạm ‖ nonce ‖ bản mã ‖ thẻ xác thực`, lưu base64.
6. Người nhận làm ngược lại bằng khóa riêng của mình.

Yêu cầu thử: mã hóa khóa ChaCha20 32 byte, một đoạn văn bản 1 KB và một file 5 MB; giải mã và so sánh với dữ liệu gốc.

Câu hỏi: (a) Vì sao sơ đồ này không bị giới hạn kích thước dữ liệu như RSA-OAEP (190 byte với khóa 2048 bit, SHA-256)? (b) Vì sao phải dùng khóa tạm mới cho mỗi lần mã hóa? (c) HKDF đóng vai trò gì, tại sao không dùng thẳng bí mật chung ECDH làm khóa?

### 4.4 Đo tốc độ (menu 7)

Lặp mỗi phép thử ít nhất 200 lần, lấy trung bình. Điền bảng (đơn vị ms):

| Đường cong | Sinh khóa | ECDH | Ký ECDSA | Xác minh ECDSA |
|---|---:|---:|---:|---:|
| nistP256 | | | | |
| nistP384 | | | | |
| nistP521 | | | | |

So sánh thêm với RSA 2048 bit và 3072 bit (ký và xác minh) bằng cách chạy lại ứng dụng RSA nếu đã có. Nhận xét:

- Phép nào nhanh hơn: ký hay xác minh? Ngược lại với RSA ở điểm nào?
- Thời gian tăng bao nhiêu lần khi chuyển từ P-256 lên P-521?
- Dựa trên mức an toàn tương đương (P-256 xấp xỉ RSA 3072 bit, khoảng 128 bit an toàn), nên chọn ECC hay RSA cho thiết bị có tài nguyên hạn chế? Vì sao?

### 4.5 SHA-512 và hiệu ứng thác đổ (menu 8)

Ứng dụng nhập một chuỗi, in SHA-512 (512 bit = 128 ký tự hex) và đếm số bit khác so với lần băm trước, theo mẫu:

| Chuỗi nhập | SHA-512 (16 ký tự hex đầu) | Số bit khác chuỗi trước |
|---|---|---|
| (chuỗi đầu tiên) | | – |
| (thêm 1 ký tự) | | …/512 |
| (nhập lại y hệt chuỗi trước) | | 0/512 |

Thí nghiệm: lấy một thông điệp ngẫu nhiên, đổi **đúng 1 bit**, so sánh hai giá trị băm; lặp **10000 lần**. In trung bình, nhỏ nhất, lớn nhất số bit thay đổi và phần trăm trên 512 bit.

Câu hỏi: (a) Giá trị trung bình kỳ vọng là bao nhiêu? Kết quả của bạn lệch bao nhiêu? (b) Tính chất này liên quan thế nào đến việc ký số trên giá trị băm? (c) Vì sao nhập lại cùng chuỗi luôn cho 0 bit khác?

### 4.6 Chữ ký số ECDSA (menu 9)

**Phần (a): quan sát.** Ký cùng một dữ liệu, cùng một khóa riêng **5 lần** bằng `ECDsa.SignData(data, HashAlgorithmName.SHA512)`. Đếm số chữ ký khác nhau và xác minh cả 5 chữ ký. Sửa 1 bit của dữ liệu rồi xác minh lại, ghi nhận kết quả.

**Phần (b): giải thích.** ECDSA tính chữ ký (r, s) với

- r = x(k·G) mod n, trong đó **k là nonce ngẫu nhiên** sinh mới mỗi lần ký;
- s = k⁻¹ · (h + r · d) mod n, với h là giá trị băm và d là khóa riêng.

Hãy giải thích vì sao 5 lần ký ra 5 chữ ký khác nhau, và vì sao điều này là **bình thường** (không làm yếu bảo mật).

**Phần (c): phân tích rủi ro của nonce.** Chứng minh bằng đại số rằng nếu hai chữ ký (r, s₁) và (r, s₂) trên hai thông điệp có băm h₁, h₂ dùng **trùng nonce k** thì kẻ quan sát tính được

- k = (h₁ − h₂) · (s₁ − s₂)⁻¹ mod n,
- d = (s₁ · k − h₁) · r⁻¹ mod n.

Từ đó nêu hậu quả khi bộ sinh số ngẫu nhiên kém hoặc nonce bị lặp (đây là nguyên nhân của một số vụ lộ khóa riêng trong thực tế). Phần này chỉ yêu cầu chứng minh trên giấy, không cần cài đặt tấn công.

**Phần (d): đề xuất chữ ký xác định.** Đề xuất và mô tả cách làm cho cùng dữ liệu, cùng khóa luôn ra **cùng một chữ ký**, nhưng vẫn an toàn. Gợi ý hướng làm:

1. **ECDSA xác định theo RFC 6979:** dẫn xuất k = HMAC-DRBG(d, h) từ khóa riêng và giá trị băm, không dùng bộ sinh ngẫu nhiên. .NET 8 `ECDsa` không hỗ trợ trực tiếp, nên cho phép dùng thư viện bên thứ ba đã được kiểm chứng (ví dụ BouncyCastle: `HMacDsaKCalculator`) hoặc mô tả thuật toán bằng sơ đồ khối.
2. **Ed25519 (EdDSA):** nonce được dẫn xuất từ băm của khóa riêng và thông điệp nên chữ ký xác định ngay từ thiết kế.
3. Phương án tự đề xuất khác (phải nêu rõ cách chứng minh nonce không lặp giữa các thông điệp khác nhau).

Lập bảng so sánh:

| Cách ký | Các lần ký có giống nhau? | Rủi ro khi bộ sinh ngẫu nhiên kém | Chuẩn hóa |
|---|---|---|---|
| ECDSA ngẫu nhiên | | | |
| ECDSA xác định (RFC 6979) | | | |
| Ed25519 | | | |

## 5. Đối chiếu bằng Python (không bắt buộc, cộng điểm)

Viết script `reference_check.py` dùng thư viện `cryptography` để tái hiện cùng thuật toán: mã hóa ChaCha20-Poly1305 file lớn, ECDH + HKDF, đo tốc độ ECC, thác đổ SHA-512 và ký ECDSA 5 lần. Xuất kết quả ra `ket_qua_tham_chieu.txt` và đối chiếu với số liệu của app C#. Nêu rõ trong báo cáo số nào đo trực tiếp bằng app C#, số nào tham chiếu từ Python.

## 6. Sản phẩm nộp

```
BaiTap-ChaCha-ECC/
├── ChaChaApp/            (Bài 1)
├── EccApp/               (Bài 2)
├── reference/            (script Python và kết quả tham chiếu)
├── docs/
│   ├── DE_BAI.md         (đề bài này)
│   ├── BAO_CAO.docx      (và bản BAO_CAO.md)
│   └── images/           (ảnh minh chứng đặt tên theo menu)
├── README.md
└── .gitignore            (loại trừ khóa bí mật và file tạo ra khi chạy)
```

Báo cáo gồm: thiết kế (bảng yêu cầu - cách làm), kết quả thực nghiệm kèm ảnh chụp từng menu, trả lời đầy đủ các câu hỏi phân tích, kết luận và hạn chế.

## 7. Thang điểm (10 điểm)

| Nội dung | Điểm |
|---|---:|
| Bài 1: các menu 1 đến 7 chạy đúng, file lớn không tràn RAM | 1.5 |
| Bài 1: AAD, phát hiện sửa đổi (menu 9), bảng đo file lớn (menu 8) | 1.5 |
| Bài 1: trả lời câu hỏi phân tích | 1.0 |
| Bài 2: sinh khóa, xuất/xem/nhập PEM (menu 1 đến 4) | 1.5 |
| Bài 2: mã hóa lai và giải mã đúng (menu 5, 6) | 1.0 |
| Bài 2: đo tốc độ và nhận xét (menu 7) | 0.5 |
| Bài 2: SHA-512 và thí nghiệm 10000 lần (menu 8) | 0.5 |
| Bài 2: ECDSA, chứng minh nonce, đề xuất chữ ký xác định (menu 9) | 1.5 |
| Báo cáo, ảnh minh chứng, README, `.gitignore` | 1.0 |
| Đối chiếu Python (cộng điểm) | +0.5 |

## 8. Lưu ý

- Đây là bài tập học tập. Hệ thống thật nên dùng các giao thức đã được kiểm chứng (TLS, age, libsodium) thay vì tự ghép sơ đồ.
- Chỉ dùng khóa do chính bạn sinh ra để thử nghiệm. Tuyệt đối không đưa khóa riêng, dù chỉ để thử, lên kho mã nguồn công khai.
- Số liệu phải trung thực: ghi rõ cấu hình máy (CPU, hệ điều hành, phiên bản .NET) ở đầu báo cáo.
