import pyspark.sql.functions as F

def run(df_conn, df_dns, df_http, df_ssl):
    # 1. Gom nhóm bảng phụ theo uid để đảm bảo quan hệ 1-1 với conn.log
    dns_agg = df_dns.groupBy("uid").agg(
        F.count("*").alias("dns_query_count"),
        F.max(F.when(F.col("rcode_name").isNotNull() & (F.col("rcode_name") != "NOERROR"), 1).otherwise(0)).alias("is_dns_error"),
        F.max(F.coalesce(F.length("query"), F.lit(0))).alias("dns_max_query_len")
    )

    http_agg = df_http.groupBy("uid").agg(
        F.count("*").alias("http_req_count"),
        F.max(F.when(F.col("status_code") >= 400, 1).otherwise(0)).alias("is_http_error"),
        F.max(F.coalesce(F.length("uri"), F.lit(0))).alias("http_max_uri_len")
    )

    ssl_agg = df_ssl.groupBy("uid").agg(
        F.max(F.when(F.col("version").isin("TLSv1.0", "TLSv1.1", "SSLv3"), 1).otherwise(0)).alias("is_obsolete_tls"),
        F.max(F.when(F.col("server_name").isNotNull(), 1).otherwise(0)).alias("ssl_has_sni")
    )

    # 2. Left Join vào bảng gốc conn
    df_joined = (
        df_conn
        .join(dns_agg, "uid", "left")
        .join(http_agg, "uid", "left")
        .join(ssl_agg, "uid", "left")
    )

    # 3. Chuẩn hóa tên cột phẳng & điền 0 cho các phiên không thuộc giao thức phụ
    return df_joined.select(
        "event_time", "uid",
        F.col("`id.orig_h`").alias("orig_h"),
        F.col("`id.resp_h`").alias("resp_h"),
        F.col("`id.orig_p`").alias("orig_p"),
        F.col("`id.resp_p`").alias("resp_p"),
        "proto",
        F.col("service_clean").alias("service"),
        F.col("duration_clean").alias("duration"),
        F.col("orig_bytes_clean").alias("orig_bytes"),
        F.col("resp_bytes_clean").alias("resp_bytes"),
        F.col("orig_pkts_clean").alias("orig_pkts"),
        F.col("resp_pkts_clean").alias("resp_pkts"),
        "conn_state", "is_conn_failed",
        "fwd_pkt_len_mean", "bwd_pkt_len_mean", "pkt_len_mean",
        "down_up_ratio", "orig_to_resp_pkt_ratio", "flow_byts_s", "flow_pkts_s",
        "syn_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "ack_flag_cnt",
        F.coalesce(F.col("dns_query_count"), F.lit(0)).alias("dns_query_count"),
        F.coalesce(F.col("is_dns_error"), F.lit(0)).alias("is_dns_error"),
        F.coalesce(F.col("dns_max_query_len"), F.lit(0)).alias("dns_max_query_len"),
        F.coalesce(F.col("http_req_count"), F.lit(0)).alias("http_req_count"),
        F.coalesce(F.col("is_http_error"), F.lit(0)).alias("is_http_error"),
        F.coalesce(F.col("http_max_uri_len"), F.lit(0)).alias("http_max_uri_len"),
        F.coalesce(F.col("is_obsolete_tls"), F.lit(0)).alias("is_obsolete_tls"),
        F.coalesce(F.col("ssl_has_sni"), F.lit(0)).alias("ssl_has_sni")
    )