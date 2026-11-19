# Schema: CICFlowMeter `analyzed_traffic.csv`

> **Công cụ sinh ra:** [CICFlowMeter](https://github.com/daixiang0/CICFlowMeter)  
> **Mô tả:** Mỗi hàng đại diện cho một **luồng mạng hai chiều (bidirectional flow)** được phân tích từ file PCAP.  
> **Tổng số trường:** 82

---

## 1. Định danh luồng (Flow Identification)

| # | Tên trường   | Kiểu dữ liệu | Mô tả                                         |
|---|--------------|--------------|-----------------------------------------------|
| 1 | `src_ip`     | string       | Địa chỉ IP nguồn                              |
| 2 | `dst_ip`     | string       | Địa chỉ IP đích                               |
| 3 | `src_port`   | integer      | Cổng nguồn                                    |
| 4 | `dst_port`   | integer      | Cổng đích                                     |
| 5 | `protocol`   | integer      | Số hiệu giao thức (6=TCP, 17=UDP, 0=ICMP...)  |
| 6 | `timestamp`  | datetime     | Thời điểm bắt đầu luồng (YYYY-MM-DD HH:MM:SS) |

---

## 2. Thời lượng luồng (Flow Duration)

| #  | Tên trường      | Kiểu dữ liệu | Đơn vị   | Mô tả                             |
|----|-----------------|--------------|----------|-----------------------------------|
| 7  | `flow_duration` | float        | microsec | Tổng thời gian tồn tại của luồng  |

---

## 3. Tốc độ luồng (Flow Rate)

| #  | Tên trường    | Kiểu dữ liệu | Đơn vị    | Mô tả                                      |
|----|---------------|--------------|-----------|---------------------------------------------|
| 8  | `flow_byts_s` | float        | bytes/s   | Tốc độ byte của toàn bộ luồng              |
| 9  | `flow_pkts_s` | float        | packets/s | Tốc độ gói tin của toàn bộ luồng           |
| 10 | `fwd_pkts_s`  | float        | packets/s | Tốc độ gói tin chiều Forward (Src -> Dst)  |
| 11 | `bwd_pkts_s`  | float        | packets/s | Tốc độ gói tin chiều Backward (Dst -> Src) |

---

## 4. Số lượng gói tin (Packet Count)

| #  | Tên trường         | Kiểu dữ liệu | Mô tả                                             |
|----|--------------------|--------------|---------------------------------------------------|
| 12 | `tot_fwd_pkts`     | integer      | Tổng số gói tin chiều Forward                     |
| 13 | `tot_bwd_pkts`     | integer      | Tổng số gói tin chiều Backward                    |
| 32 | `fwd_act_data_pkts`| integer      | Số gói Forward có chứa dữ liệu thực (payload > 0) |

---

## 5. Kích thước gói tin (Packet Length)

| #  | Tên trường         | Kiểu dữ liệu | Đơn vị | Mô tả                                          |
|----|--------------------|--------------|--------|------------------------------------------------|
| 14 | `totlen_fwd_pkts`  | integer      | bytes  | Tổng số byte payload chiều Forward             |
| 15 | `totlen_bwd_pkts`  | integer      | bytes  | Tổng số byte payload chiều Backward            |
| 16 | `fwd_pkt_len_max`  | float        | bytes  | Kích thước gói tin Forward lớn nhất            |
| 17 | `fwd_pkt_len_min`  | float        | bytes  | Kích thước gói tin Forward nhỏ nhất            |
| 18 | `fwd_pkt_len_mean` | float        | bytes  | Kích thước gói tin Forward trung bình          |
| 19 | `fwd_pkt_len_std`  | float        | bytes  | Độ lệch chuẩn kích thước gói tin Forward       |
| 20 | `bwd_pkt_len_max`  | float        | bytes  | Kích thước gói tin Backward lớn nhất           |
| 21 | `bwd_pkt_len_min`  | float        | bytes  | Kích thước gói tin Backward nhỏ nhất           |
| 22 | `bwd_pkt_len_mean` | float        | bytes  | Kích thước gói tin Backward trung bình         |
| 23 | `bwd_pkt_len_std`  | float        | bytes  | Độ lệch chuẩn kích thước gói tin Backward      |
| 24 | `pkt_len_max`      | float        | bytes  | Kích thước gói tin lớn nhất (cả 2 chiều)       |
| 25 | `pkt_len_min`      | float        | bytes  | Kích thước gói tin nhỏ nhất (cả 2 chiều)       |
| 26 | `pkt_len_mean`     | float        | bytes  | Kích thước gói tin trung bình (cả 2 chiều)     |
| 27 | `pkt_len_std`      | float        | bytes  | Độ lệch chuẩn kích thước gói tin (cả 2 chiều)  |
| 28 | `pkt_len_var`      | float        | bytes2 | Phương sai kích thước gói tin (cả 2 chiều)     |
| 59 | `pkt_size_avg`     | float        | bytes  | Kích thước gói tin trung bình (toàn luồng)     |

---

## 6. Kích thước Header (Header Length)

| #  | Tên trường         | Kiểu dữ liệu | Đơn vị | Mô tả                                        |
|----|--------------------|--------------|--------|----------------------------------------------|
| 29 | `fwd_header_len`   | integer      | bytes  | Tổng kích thước header chiều Forward         |
| 30 | `bwd_header_len`   | integer      | bytes  | Tổng kích thước header chiều Backward        |
| 31 | `fwd_seg_size_min` | integer      | bytes  | Kích thước segment nhỏ nhất chiều Forward    |
| 76 | `fwd_seg_size_avg` | float        | bytes  | Kích thước segment trung bình chiều Forward  |
| 77 | `bwd_seg_size_avg` | float        | bytes  | Kích thước segment trung bình chiều Backward |

---

## 7. Thời gian giữa các gói tin - IAT (Inter-Arrival Time)

| #  | Tên trường      | Kiểu dữ liệu | Đơn vị   | Mô tả                                  |
|----|-----------------|--------------|----------|----------------------------------------|
| 33 | `flow_iat_mean` | float        | microsec | IAT trung bình của toàn bộ luồng       |
| 34 | `flow_iat_max`  | float        | microsec | IAT lớn nhất của toàn bộ luồng         |
| 35 | `flow_iat_min`  | float        | microsec | IAT nhỏ nhất của toàn bộ luồng         |
| 36 | `flow_iat_std`  | float        | microsec | Độ lệch chuẩn IAT của toàn bộ luồng    |
| 37 | `fwd_iat_tot`   | float        | microsec | Tổng IAT chiều Forward                 |
| 38 | `fwd_iat_max`   | float        | microsec | IAT lớn nhất chiều Forward             |
| 39 | `fwd_iat_min`   | float        | microsec | IAT nhỏ nhất chiều Forward             |
| 40 | `fwd_iat_mean`  | float        | microsec | IAT trung bình chiều Forward           |
| 41 | `fwd_iat_std`   | float        | microsec | Độ lệch chuẩn IAT chiều Forward        |
| 42 | `bwd_iat_tot`   | float        | microsec | Tổng IAT chiều Backward                |
| 43 | `bwd_iat_max`   | float        | microsec | IAT lớn nhất chiều Backward            |
| 44 | `bwd_iat_min`   | float        | microsec | IAT nhỏ nhất chiều Backward            |
| 45 | `bwd_iat_mean`  | float        | microsec | IAT trung bình chiều Backward          |
| 46 | `bwd_iat_std`   | float        | microsec | Độ lệch chuẩn IAT chiều Backward       |

---

## 8. Co TCP (TCP Flags)

| #  | Tên trường       | Kiểu dữ liệu | Mô tả                                             |
|----|------------------|--------------|---------------------------------------------------|
| 47 | `fwd_psh_flags`  | integer      | Số gói Forward có cờ PSH được bật                 |
| 48 | `bwd_psh_flags`  | integer      | Số gói Backward có cờ PSH được bật                |
| 49 | `fwd_urg_flags`  | integer      | Số gói Forward có cờ URG được bật                 |
| 50 | `bwd_urg_flags`  | integer      | Số gói Backward có cờ URG được bật                |
| 51 | `fin_flag_cnt`   | integer      | Tổng số gói có cờ FIN (Kết thúc kết nối)          |
| 52 | `syn_flag_cnt`   | integer      | Tổng số gói có cờ SYN (Bắt đầu kết nối)           |
| 53 | `rst_flag_cnt`   | integer      | Tổng số gói có cờ RST (Reset kết nối)             |
| 54 | `psh_flag_cnt`   | integer      | Tổng số gói có cờ PSH (Đẩy dữ liệu ngay)         |
| 55 | `ack_flag_cnt`   | integer      | Tổng số gói có cờ ACK (Xác nhận)                  |
| 56 | `urg_flag_cnt`   | integer      | Tổng số gói có cờ URG (Dữ liệu khẩn cấp)         |
| 57 | `ece_flag_cnt`   | integer      | Tổng số gói có cờ ECE (Báo tắc nghẽn)             |
| 78 | `cwr_flag_count` | integer      | Tổng số gói có cờ CWR (Giảm cửa sổ tắc nghẽn)    |

---

## 9. Ty le & Thong ke tong hop (Ratios & Aggregates)

| #  | Tên trường      | Kiểu dữ liệu | Mô tả                                             |
|----|-----------------|--------------|---------------------------------------------------|
| 58 | `down_up_ratio` | float        | Tỷ lệ số gói Backward / Forward (Download/Upload) |

---

## 10. Cua so TCP ban dau (Initial TCP Window)

| #  | Tên trường          | Kiểu dữ liệu | Đơn vị | Mô tả                                                   |
|----|---------------------|--------------|--------|---------------------------------------------------------|
| 60 | `init_fwd_win_byts` | integer      | bytes  | Kích thước cửa sổ TCP trong gói SYN đầu tiên (Forward)  |
| 61 | `init_bwd_win_byts` | integer      | bytes  | Kích thước cửa sổ TCP trong gói SYN đầu tiên (Backward) |

---

## 11. Trang thai Active / Idle cua luong

| #  | Tên trường    | Kiểu dữ liệu | Đơn vị   | Mô tả                                          |
|----|---------------|--------------|----------|------------------------------------------------|
| 62 | `active_max`  | float        | microsec | Thời gian hoạt động liên tục dài nhất          |
| 63 | `active_min`  | float        | microsec | Thời gian hoạt động liên tục ngắn nhất         |
| 64 | `active_mean` | float        | microsec | Thời gian hoạt động liên tục trung bình        |
| 65 | `active_std`  | float        | microsec | Độ lệch chuẩn thời gian hoạt động liên tục     |
| 66 | `idle_max`    | float        | microsec | Thời gian nhàn rỗi dài nhất                    |
| 67 | `idle_min`    | float        | microsec | Thời gian nhàn rỗi ngắn nhất                   |
| 68 | `idle_mean`   | float        | microsec | Thời gian nhàn rỗi trung bình                  |
| 69 | `idle_std`    | float        | microsec | Độ lệch chuẩn thời gian nhàn rỗi               |

---

## 12. Thong ke theo Bulk (Luong du lieu lon lien tuc)

> **Bulk** là một chuỗi các gói tin liên tiếp trong cùng một chiều. Các trường này đo tốc độ và mật độ của các "đợt truyền dữ liệu lớn".

| #  | Tên trường          | Kiểu dữ liệu | Mô tả                                           |
|----|---------------------|--------------|-------------------------------------------------|
| 70 | `fwd_byts_b_avg`    | float        | Số byte trung bình mỗi bulk chiều Forward       |
| 71 | `fwd_pkts_b_avg`    | float        | Số gói tin trung bình mỗi bulk chiều Forward    |
| 72 | `bwd_byts_b_avg`    | float        | Số byte trung bình mỗi bulk chiều Backward      |
| 73 | `bwd_pkts_b_avg`    | float        | Số gói tin trung bình mỗi bulk chiều Backward   |
| 74 | `fwd_blk_rate_avg`  | float        | Tốc độ bulk trung bình chiều Forward (bytes/s)  |
| 75 | `bwd_blk_rate_avg`  | float        | Tốc độ bulk trung bình chiều Backward (bytes/s) |

---

## 13. Thong ke theo Subflow (Luong con)

> **Subflow** là một phân đoạn nhỏ bên trong luồng lớn, dùng để đo chi tiết từng giai đoạn của kết nối.

| #  | Tên trường          | Kiểu dữ liệu | Mô tả                                       |
|----|---------------------|--------------|---------------------------------------------|
| 79 | `subflow_fwd_pkts`  | integer      | Số gói tin trung bình mỗi subflow Forward   |
| 80 | `subflow_bwd_pkts`  | integer      | Số gói tin trung bình mỗi subflow Backward  |
| 81 | `subflow_fwd_byts`  | integer      | Số byte trung bình mỗi subflow Forward      |
| 82 | `subflow_bwd_byts`  | integer      | Số byte trung bình mỗi subflow Backward     |

---

## Tóm tắt nhóm trường

| Nhóm                       | Số trường | Trường số | Trường chuỗi |
|----------------------------|-----------|-----------|--------------|
| Định danh luồng            | 6         | 4         | 2            |
| Thời lượng & Tốc độ        | 5         | 5         | 0            |
| Số lượng gói tin           | 3         | 3         | 0            |
| Kích thước gói tin         | 13        | 13        | 0            |
| Kích thước Header          | 5         | 5         | 0            |
| Inter-Arrival Time (IAT)   | 14        | 14        | 0            |
| Cờ TCP                     | 12        | 12        | 0            |
| Tỷ lệ tổng hợp             | 1         | 1         | 0            |
| Cửa sổ TCP ban đầu         | 2         | 2         | 0            |
| Active / Idle              | 8         | 8         | 0            |
| Bulk                       | 6         | 6         | 0            |
| Subflow                    | 4         | 4         | 0            |
| **Tổng cộng**              | **82**    | **80**    | **2**        |

---

## Ghi chú quan trọng khi sử dụng

- **Chiều Forward (fwd):** Hướng từ Nguồn (`src_ip:src_port`) sang Đích (`dst_ip:dst_port`)
- **Chiều Backward (bwd):** Hướng từ Đích (`dst_ip:dst_port`) về Nguồn (`src_ip:src_port`)
- Các trường `src_ip`, `dst_ip`, `timestamp` là kiểu **chuỗi (string)**, không thể đưa trực tiếp vào `VectorAssembler` của PySpark ML. Cần loại trừ hoặc mã hóa (LabelEncoder) trước khi huấn luyện mô hình.
- Các trường **IAT** và **flow_duration** có đơn vị **microsecond (µs)**. Chia cho `1,000,000` để chuyển sang giây.
- Các trường có thể chứa giá trị âm hoặc `Infinity` khi luồng chỉ có 1 gói tin (ví dụ: `flow_iat_min`, `fwd_iat_min`). Cần xử lý trước khi đưa vào mô hình.
