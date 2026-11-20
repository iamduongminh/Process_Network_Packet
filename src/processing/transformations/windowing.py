import pyspark.sql.functions as F

def run(df_gold_flow, window_duration="5 seconds", slide_duration="2 seconds"):
    df_windowed = (
        df_gold_flow
        .filter(F.col("orig_h").isNotNull())
        .groupBy(
            F.window(F.col("event_time"), window_duration, slide_duration).alias("time_window"),
            F.col("orig_h").alias("src_ip")
        )
        .agg(
            F.count("uid").alias("concurrent_flows"),
            F.countDistinct("resp_h").alias("dst_ip_diversity"),
            F.countDistinct("resp_p").alias("dst_port_diversity"),
            F.sum("orig_bytes").alias("total_orig_bytes_window"),
            F.sum("resp_bytes").alias("total_resp_bytes_window"),
            F.avg("is_conn_failed").alias("failed_conn_ratio_window"),
            (F.sum("syn_flag_cnt") / (F.sum("ack_flag_cnt") + F.lit(1.0))).alias("syn_to_ack_ratio_window"),
            F.sum("is_dns_error").alias("total_dns_errors_window"),
            F.sum("is_http_error").alias("total_http_errors_window")
        )
    )

    return df_windowed.select(
        F.col("time_window.start").alias("window_start"),
        F.col("time_window.end").alias("window_end"),
        "src_ip",
        "concurrent_flows",
        "dst_ip_diversity",
        "dst_port_diversity",
        "total_orig_bytes_window",
        "total_resp_bytes_window",
        "failed_conn_ratio_window",
        "syn_to_ack_ratio_window",
        "total_dns_errors_window",
        "total_http_errors_window"
    )