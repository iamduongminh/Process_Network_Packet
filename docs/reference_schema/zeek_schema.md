# Cấu trúc Schema các Zeek Log Files

Tài liệu này tổng hợp cấu trúc Schema chi tiết cho các file log được parse từ Zeek dưới định dạng NDJSON (JSON Lines). Kiểu dữ liệu được chuẩn hóa theo kiểu dữ liệu tương thích với **PySpark DataFrame**.

---

## 1. `conn.log` (Lưu lượng kết nối cơ sở)
Cột sống lưng của toàn bộ dữ liệu mạng. Tất cả các log khác đều JOIN với bảng này thông qua trường `uid`.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp bắt đầu kết nối (Epoch time). |
| `uid` | String | Mã định danh duy nhất cho phiên kết nối. |
| `id.orig_h` | String | Địa chỉ IP máy trạm gửi yêu cầu (Nguồn). |
| `id.orig_p` | Integer | Cổng (Port) máy trạm gửi yêu cầu. |
| `id.resp_h` | String | Địa chỉ IP máy chủ nhận yêu cầu (Đích). |
| `id.resp_p` | Integer | Cổng (Port) máy chủ nhận yêu cầu. |
| `proto` | String | Giao thức tầng Transport (`tcp`, `udp`, `icmp`). |
| `service` | String | Giao thức tầng Application (ví dụ: `http`, `dns`, `ssl`). |
| `duration` | Double | Thời gian tồn tại của kết nối (tính bằng giây). |
| `orig_bytes` | Long | Số byte payload từ Nguồn gửi đi. |
| `resp_bytes` | Long | Số byte payload từ Đích trả về. |
| `conn_state` | String | Trạng thái kết nối TCP (ví dụ: `S0`, `SF`, `REJ`). |
| `local_orig` | Boolean | Kết nối xuất phát từ mạng nội bộ (true/false). |
| `local_resp` | Boolean | Kết nối đích đến là mạng nội bộ (true/false). |
| `missed_bytes` | Long | Số byte bị mất trong quá trình phân tích gói tin. |
| `history` | String | Chuỗi ký tự mô tả lịch sử cờ TCP (ví dụ: `ShADadFf`). |
| `orig_pkts` | Long | Số lượng gói tin Nguồn gửi đi. |
| `orig_ip_bytes` | Long | Tổng số byte tầng IP từ Nguồn. |
| `resp_pkts` | Long | Số lượng gói tin Đích trả về. |
| `resp_ip_bytes` | Long | Tổng số byte tầng IP từ Đích. |

---

## 2. `dns.log` (Truy vấn tên miền)
Quan trọng để phát hiện thiết bị dính mã độc liên lạc với máy chủ C&C (Command & Control) hoặc kỹ thuật DNS Tunneling.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp giao dịch DNS. |
| `uid` | String | Mã định danh kết nối (JOIN với `conn.log`). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port nguồn. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port đích (DNS Server). |
| `proto` | String | Giao thức truyền tải (`udp` hoặc `tcp`). |
| `trans_id` | Integer | ID của giao dịch DNS. |
| `query` | String | Tên miền được truy vấn (VD: `google.com`). |
| `qclass_name` | String | Lớp truy vấn (thường là `C_INTERNET`). |
| `qtype_name` | String | Loại bản ghi truy vấn (VD: `A`, `AAAA`, `MX`, `TXT`). |
| `rcode_name` | String | Mã phản hồi (VD: `NOERROR`, `NXDOMAIN`). |
| `AA` | Boolean | Phản hồi từ máy chủ ủy quyền (Authoritative Answer). |
| `TC` | Boolean | Phản hồi bị cắt ngắn (Truncated). |
| `RD` | Boolean | Yêu cầu đệ quy (Recursion Desired). |
| `RA` | Boolean | Máy chủ hỗ trợ đệ quy (Recursion Available). |
| `answers` | Array[String] | Danh sách các IP/Tên miền trả về. |
| `TTLs` | Array[Double] | Danh sách Time-To-Live tương ứng cho các bản ghi. |
| `rejected` | Boolean | Yêu cầu DNS có bị từ chối hay không. |

---

## 3. `http.log` (Giao thức Web HTTP/1.x)
Sử dụng để trích xuất các đặc trưng tấn công Web, rà quét ứng dụng hoặc tải tệp độc hại.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp ghi nhận yêu cầu HTTP. |
| `uid` | String | Mã định danh kết nối (JOIN với `conn.log`). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port client. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port Web server. |
| `trans_depth` | Integer | Thứ tự của pipelined request trong cùng kết nối TCP. |
| `method` | String | Phương thức HTTP (`GET`, `POST`, `PUT`, `DELETE`...). |
| `host` | String | Header `Host` của yêu cầu. |
| `uri` | String | Đường dẫn URI truy cập. |
| `referrer` | String | Header `Referer` chỉ nguồn chuyển hướng. |
| `user_agent` | String | Header `User-Agent` của trình duyệt / công cụ. |
| `request_body_len` | Long | Độ dài dữ liệu gửi đi (bytes). |
| `response_body_len` | Long | Độ dài dữ liệu nhận về (bytes). |
| `status_code` | Integer | Mã phản hồi HTTP (VD: `200`, `404`, `500`). |
| `status_msg` | String | Thông điệp phản hồi (VD: `OK`, `Not Found`). |
| `tags` | Array[String] | Các thẻ đánh dấu tính chất giao dịch của Zeek. |
| `resp_fuids` | Array[String] | Danh sách File ID truyền trong response (JOIN `files.log`). |

---

## 4. `ssl.log` (Giao tiếp mã hóa TLS/SSL)
Hữu ích để bóc tách dấu vân tay mã hóa (như JA3/JA3S) để phát hiện Botnet hoặc Malware dùng SSL.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp bắt tay SSL/TLS. |
| `uid` | String | Mã định danh kết nối (JOIN với `conn.log`). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port client. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port server. |
| `version` | String | Phiên bản SSL/TLS (VD: `TLSv12`, `TLSv13`). |
| `cipher` | String | Bộ mã hóa (Cipher Suite) được thống nhất. |
| `curve` | String | Đường cong elip dùng trong trao đổi khóa (ECDHE). |
| `server_name` | String | Tên miền máy chủ trong trường SNI (Server Name Indication). |
| `resumed` | Boolean | Phân đoạn session cũ có được tái sử dụng hay không. |
| `established` | Boolean | Quá trình bắt tay TLS có thành công hay không. |
| `cert_chain_fuids` | Array[String] | Danh sách File ID chuỗi chứng chỉ (JOIN `x509.log`). |
| `client_cert_chain_fuids`| Array[String]| File ID chứng chỉ phía Client (nếu có mtls). |

---

## 5. `x509.log` (Thông tin chứng chỉ số X.509)
Bóc tách chi tiết chứng chỉ SSL/TLS được truyền tải qua mạng.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp phân tích chứng chỉ. |
| `id` | String | Mã băm định danh của chứng chỉ (File ID). |
| `certificate.version` | Integer | Phiên bản chuẩn X.509. |
| `certificate.serial` | String | Số Serial duy nhất của chứng chỉ. |
| `certificate.subject` | String | Thông tin chủ sở hữu chứng chỉ. |
| `certificate.issuer` | String | Tổ chức phát hành chứng chỉ (CA). |
| `certificate.not_valid_before` | Double | Thời gian bắt đầu có hiệu lực (Epoch time). |
| `certificate.not_valid_after` | Double | Thời gian hết hạn (Epoch time). |
| `certificate.key_alg` | String | Thuật toán khóa công khai (VD: `rsaEncryption`). |
| `certificate.sig_alg` | String | Thuật toán chữ ký số (VD: `sha256WithRSAEncryption`). |
| `san.dns` | Array[String] | Danh sách các tên miền phụ/thay thế (SAN). |

---

## 6. `files.log` (Phân tích tệp tin trên mạng)
Theo dõi các tệp tin được truyền qua các giao thức (HTTP, SMTP, FTP...). Rất quan trọng để kiểm tra Hash Malware.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp ghi nhận tệp. |
| `fuid` | String | Mã định danh duy nhất của tệp (File UID). |
| `tx_hosts` | Array[String] | Danh sách IP truyền tệp (Gửi). |
| `rx_hosts` | Array[String] | Danh sách IP nhận tệp (Nhận). |
| `conn_uids` | Array[String] | Danh sách `uid` kết nối chứa tệp này. |
| `source` | String | Giao thức nguồn truyền tệp (VD: `HTTP`, `SMTP`). |
| `depth` | Integer | Độ sâu pipeline truyền tệp. |
| `mime_type` | String | Định dạng tệp tin (VD: `application/x-dosexec`). |
| `filename` | String | Tên tệp tin (nếu có). |
| `seen_bytes` | Long | Số byte thu thập được từ luồng mạng. |
| `total_bytes` | Long | Tổng dung lượng thực tế của tệp (nếu xác định được). |
| `missing_bytes` | Long | Số byte tệp tin bị khuyết thiếu trên mạng. |
| `overflow_bytes` | Long | Số byte vượt ngưỡng bộ đệm ghi nhận. |
| `md5` / `sha1` / `sha256` | String | Các mã băm tệp tin phục vụ tra cứu Threat Intelligence. |

---

## 7. `weird.log` (Bất thường giao thức)
Ghi lại các hành vi vi phạm chuẩn RFC giao thức mạng (dấu hiệu rà quét ẩn, khai thác lỗ hổng hoặc gói tin lỗi).

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp ghi nhận bất thường. |
| `uid` | String | Mã định danh phiên kết nối (nếu có). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port nguồn. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port đích. |
| `name` | String | Tên loại lỗi bất thường (VD: `bad_TCP_checksum`). |
| `addl` | String | Thông tin bổ sung chi tiết về lỗi. |
| `notice` | Boolean | Đánh dấu lỗi có đủ nguy hiểm để kích hoạt Cảnh báo không. |
| `peer` | String | Tiến trình/thành phần Zeek phát hiện ra lỗi. |

---

## 8. `quic.log` (Giao thức HTTP/3)
Dữ liệu của giao thức mã hóa nền UDP được áp dụng rộng rãi trên các dịch vụ web hiện đại.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp kết nối QUIC. |
| `uid` | String | Mã định danh kết nối (JOIN với `conn.log`). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port client. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port server. |
| `version` | String | Phiên bản QUIC sử dụng. |
| `client_initial_dcid` | String | Destination Connection ID ban đầu từ client. |
| `server_initial_scid` | String | Source Connection ID từ server trả về. |
| `server_name` | String | Tên miền SNI máy chủ đích. |
| `history` | String | Lịch sử cờ trạng thái bắt tay giao thức QUIC. |

---

## 9. `dhcp.log` (Cấp phát địa chỉ IP động)
Theo dõi hành vi cấp phát IP và ánh xạ địa chỉ MAC trong mạng nội bộ.

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp sự kiện DHCP. |
| `uids` | Array[String] | Danh sách `uid` kết nối liên quan. |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port thiết bị yêu cầu (thường là Port 68). |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port DHCP Server (thường là Port 67). |
| `mac` | String | Địa chỉ MAC phần cứng của thiết bị yêu cầu. |
| `assigned_ip` | String | Địa chỉ IP được cấp phát cho thiết bị. |
| `lease_time` | Double | Thời hạn cho thuê địa chỉ IP (tính bằng giây). |
| `trans_id` | Long | ID giao dịch DHCP. |

---

## 10. `ntp.log` (Đồng bộ thời gian mạng)
Ghi nhận giao thức NTP, hữu ích phát hiện tấn công DDoS khuếch đại (NTP Amplification Attack).

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp gói tin NTP. |
| `uid` | String | Mã định danh kết nối (JOIN với `conn.log`). |
| `id.orig_h` / `id.orig_p` | String / Integer | IP / Port client gửi đồng bộ. |
| `id.resp_h` / `id.resp_p` | String / Integer | IP / Port NTP Server (Port 123). |
| `version` | Integer | Phiên bản NTP (thường là 3 hoặc 4). |
| `mode` | Integer | Chế độ hoạt động (1: Active, 3: Client, 4: Server...). |
| `stratum` | Integer | Cấp độ phân tầng thời gian của máy chủ. |
| `poll` | Double | Khoảng thời gian gửi câu hỏi đồng bộ (lũy thừa cơ số 2). |

---

## 11. `ocsp.log` (Trạng thái thu hồi chứng chỉ)
Giao thức kiểm tra trạng thái thu hồi chứng chỉ trực tuyến (Online Certificate Status Protocol).

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp phản hồi OCSP. |
| `id` | String | Mã định danh tệp tin phản hồi (File ID). |
| `hashAlgorithm` | String | Thuật toán băm sử dụng trong truy vấn OCSP. |
| `issuerNameHash` | String | Hash tên tổ chức phát hành (CA). |
| `issuerKeyHash` | String | Hash khóa công khai của CA. |
| `serialNumber` | String | Số Serial của chứng chỉ cần kiểm tra. |
| `certStatus` | String | Trạng thái chứng chỉ (`good`, `revoked`, `unknown`). |
| `revoketime` | Double | Thời điểm chứng chỉ bị thu hồi (nếu status = `revoked`). |

---

## 12. `packet_filter.log` (Bộ lọc chặn bắt gói tin)
Log quản lý hệ thống của Zeek, ghi nhận trạng thái áp dụng quy tắc lọc gói tin (BPF rules).

| Trường dữ liệu (Field) | Kiểu dữ liệu (Spark Type) | Mô tả (Description) |
| :--- | :--- | :--- |
| `ts` | Double | Timestamp áp dụng luật BPF. |
| `node` | String | Tên nút Zeek áp dụng luật (trong cụm cluster). |
| `filter` | String | Chuỗi biểu thức BPF (Berkeley Packet Filter) đang áp dụng. |
| `init` | Boolean | Đánh dấu đây có phải luật khởi tạo ban đầu hay không. |
| `success` | Boolean | Cờ báo luật BPF có biên dịch và áp dụng thành công không. |