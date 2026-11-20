@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/smb
@load base/protocols/krb
@load base/protocols/ntlm

# Đảm bảo luôn xuất JSON phẳng và không bỏ sót gói tin lỗi checksum trên card mạng ảo
redef LogAscii::use_json = T;
redef ignore_checksums = T;

# ==============================================================================
# MODULE 1: ĐỊNH NGHĨA LUỒNG LOG THỐNG KÊ VI MÔ GÓI TIN (flow_stats.log)
# ==============================================================================
module FlowStats;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                 time    &log;
        uid:                string  &log;
        id:                 conn_id &log;
        # Phân phối kích thước gói tin (tương đương CICFlowMeter Pkt Len Min/Max/Mean/Std)
        pkt_len_min:        count   &log &default=0;
        pkt_len_max:        count   &log &default=0;
        pkt_len_mean:       double  &log &default=0.0;
        pkt_len_std:        double  &log &default=0.0;
        # Phân phối độ trễ giữa các gói tin (tương đương Flow IAT Min/Max/Mean/Std)
        iat_min:            double  &log &default=0.0;
        iat_max:            double  &log &default=0.0;
        iat_mean:           double  &log &default=0.0;
        iat_std:            double  &log &default=0.0;
        # Đặc trưng tầng giao vận (TCP Window & Header)
        init_fwd_win_bytes: int     &log &default=-1;
        init_bwd_win_bytes: int     &log &default=-1;
        fwd_header_bytes:   count   &log &default=0;
        bwd_header_bytes:   count   &log &default=0;
    };

    # Cấu trúc tích lũy trực tuyến Welford O(1) bộ nhớ cho mỗi phiên kết nối
    type FlowTracker: record {
        pkt_count:          count   &default=0;
        len_min:            count   &default=4294967295;
        len_max:            count   &default=0;
        len_mean:           double  &default=0.0;
        len_m2:             double  &default=0.0;

        last_ts:            time    &default=double_to_time(0.0);
        iat_count:          count   &default=0;
        iat_min:            double  &default=999999999.0;
        iat_max:            double  &default=0.0;
        iat_mean:           double  &default=0.0;
        iat_m2:             double  &default=0.0;

        init_fwd_win:       int     &default=-1;
        init_bwd_win:       int     &default=-1;
        fwd_hdr_len:        count   &default=0;
        bwd_hdr_len:        count   &default=0;
    };
}

global trackers: table[string] of FlowTracker;

# Hàm cập nhật thống kê Welford từng gói tin
function update_tracker(tr: FlowTracker, pkt_ts: time, pkt_len: count) {
    tr$pkt_count += 1;
    if ( pkt_len < tr$len_min ) tr$len_min = pkt_len;
    if ( pkt_len > tr$len_max ) tr$len_max = pkt_len;

    local delta_len = (pkt_len * 1.0) - tr$len_mean;
    tr$len_mean += delta_len / tr$pkt_count;
    tr$len_m2 += delta_len * ((pkt_len * 1.0) - tr$len_mean);

    if ( tr$pkt_count > 1 ) {
        local iat = interval_to_double(pkt_ts - tr$last_ts);
        if ( iat < 0.0 ) iat = 0.0;
        tr$iat_count += 1;
        if ( iat < tr$iat_min ) tr$iat_min = iat;
        if ( iat > tr$iat_max ) tr$iat_max = iat;

        local delta_iat = iat - tr$iat_mean;
        tr$iat_mean += delta_iat / tr$iat_count;
        tr$iat_m2 += delta_iat * (iat - tr$iat_mean);
    }
    tr$last_ts = pkt_ts;
}

# Bắt sự kiện từng gói tin của kết nối
event new_packet(c: connection, p: pkt_hdr) {
    local uid = c$uid;
    if ( uid !in trackers )
        trackers[uid] = FlowTracker();

    local tr = trackers[uid];
    local pkt_len: count = 0;
    local hdr_len: count = 0;

    if ( p?$ip ) {
        pkt_len = p$ip$len;
        hdr_len = p$ip$hl;
    } else if ( p?$ip6 ) {
        pkt_len = p$ip6$len + 40;
        hdr_len = 40;
    }

    local is_orig = (p?$ip && p$ip$src == c$id$orig_h) || (p?$ip6 && p$ip6$src == c$id$orig_h);

    if ( p?$tcp ) {
        hdr_len += p$tcp$hl;
        if ( is_orig && tr$init_fwd_win == -1 )
            tr$init_fwd_win = p$tcp$win;
        else if ( !is_orig && tr$init_bwd_win == -1 )
            tr$init_bwd_win = p$tcp$win;
    } else if ( p?$udp ) {
        hdr_len += 8;
    }

    if ( is_orig )
        tr$fwd_hdr_len += hdr_len;
    else
        tr$bwd_hdr_len += hdr_len;

    update_tracker(tr, network_time(), pkt_len);
}

# Khi phiên kết nối kết thúc -> tính độ lệch chuẩn và ghi ra flow_stats.log
event connection_state_remove(c: connection) {
    local uid = c$uid;
    if ( uid !in trackers ) return;

    local tr = trackers[uid];
    local len_std = 0.0;
    if ( tr$pkt_count > 1 )
        len_std = sqrt(tr$len_m2 / (tr$pkt_count - 1));

    local iat_std = 0.0;
    if ( tr$iat_count > 1 )
        iat_std = sqrt(tr$iat_m2 / (tr$iat_count - 1));

    local rec: Info = [
        $ts                 = c$start_time,
        $uid                = uid,
        $id                 = c$id,
        $pkt_len_min        = (tr$pkt_count > 0 ? tr$len_min : 0),
        $pkt_len_max        = tr$len_max,
        $pkt_len_mean       = tr$len_mean,
        $pkt_len_std        = len_std,
        $iat_min            = (tr$iat_count > 0 ? tr$iat_min : 0.0),
        $iat_max            = tr$iat_max,
        $iat_mean           = tr$iat_mean,
        $iat_std            = iat_std,
        $init_fwd_win_bytes = tr$init_fwd_win,
        $init_bwd_win_bytes = tr$init_bwd_win,
        $fwd_header_bytes   = tr$fwd_hdr_len,
        $bwd_header_bytes   = tr$bwd_hdr_len
    ];

    Log::write(LOG, rec);
    delete trackers[uid];
}

module GLOBAL;

# ==============================================================================
# MODULE 2: CHẶN TẤT CẢ LUỒNG RÁC, CHỈ GIỮ 8 LUỒNG PHỤC VỤ PHÁT HIỆN BẤT THƯỜNG
# ==============================================================================
hook Log::log_stream_policy(rec: any, id: Log::ID) {
    if ( id != Conn::LOG &&
         id != DNS::LOG &&
         id != HTTP::LOG &&
         id != SSL::LOG &&
         id != FlowStats::LOG &&
         id != SMB::FILES_LOG &&
         id != KRB::LOG &&
         id != NTLM::LOG ) {
        break;
    }
}

# ==============================================================================
# MODULE 3: ĐĂNG KÝ FILTER & CHỌN CỘT CHO TỪNG LUỒNG LOG
# ==============================================================================
event zeek_init() &priority=-5 {
    # Tạo stream flow_stats.log
    Log::create_stream(FlowStats::LOG, [$columns=FlowStats::Info, $path="flow_stats"]);

    # 1. conn.log (bổ sung missed_bytes)
    local f_conn: Log::Filter = [
        $name = "raw-conn",
        $path = "conn",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "proto", "service", "duration", "orig_bytes", "resp_bytes",
                       "orig_pkts", "resp_pkts", "history", "conn_state", "missed_bytes")
    ];
    Log::remove_filter(Conn::LOG, "default");
    Log::add_filter(Conn::LOG, f_conn);

    # 2. dns.log
    local f_dns: Log::Filter = [
        $name = "raw-dns",
        $path = "dns",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "proto", "query", "qtype_name", "rcode_name", "answers")
    ];
    Log::remove_filter(DNS::LOG, "default");
    Log::add_filter(DNS::LOG, f_dns);

    # 3. http.log
    local f_http: Log::Filter = [
        $name = "raw-http",
        $path = "http",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "method", "host", "uri", "user_agent", "status_code")
    ];
    Log::remove_filter(HTTP::LOG, "default");
    Log::add_filter(HTTP::LOG, f_http);

    # 4. ssl.log (bổ sung validation_status)
    local f_ssl: Log::Filter = [
        $name = "raw-ssl",
        $path = "ssl",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "version", "cipher", "server_name", "validation_status")
    ];
    Log::remove_filter(SSL::LOG, "default");
    Log::add_filter(SSL::LOG, f_ssl);

    # 5. smb_files.log (Giám sát truy cập/mã hóa file qua mạng nội bộ)
    local f_smb: Log::Filter = [
        $name = "raw-smb",
        $path = "smb_files",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "action", "name", "size")
    ];
    Log::remove_filter(SMB::FILES_LOG, "default");
    Log::add_filter(SMB::FILES_LOG, f_smb);

    # 6. kerberos.log (Giám sát Kerberoasting / Golden Ticket / Brute-force AD)
    local f_krb: Log::Filter = [
        $name = "raw-krb",
        $path = "kerberos",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "request_type", "client", "service", "success", "error_msg")
    ];
    Log::remove_filter(KRB::LOG, "default");
    Log::add_filter(KRB::LOG, f_krb);

    # 7. ntlm.log (Giám sát Pass-the-Hash / NTLM Relay)
    local f_ntlm: Log::Filter = [
        $name = "raw-ntlm",
        $path = "ntlm",
        $include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "username", "hostname", "domainname", "success")
    ];
    Log::remove_filter(NTLM::LOG, "default");
    Log::add_filter(NTLM::LOG, f_ntlm);
}