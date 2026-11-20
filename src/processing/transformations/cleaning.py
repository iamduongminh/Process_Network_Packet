import pyspark.sql.functions as F

def run(df_conn):
    df_clean = (
        df_conn
        .withColumn("duration_clean", F.coalesce(F.col("duration"), F.lit(0.0)))
        .withColumn("orig_bytes_clean", F.coalesce(F.col("orig_bytes"), F.lit(0)))
        .withColumn("resp_bytes_clean", F.coalesce(F.col("resp_bytes"), F.lit(0)))
        .withColumn("orig_pkts_clean", F.coalesce(F.col("orig_pkts"), F.lit(0)))
        .withColumn("resp_pkts_clean", F.coalesce(F.col("resp_pkts"), F.lit(0)))
        .withColumn("history_clean", F.coalesce(F.col("history"), F.lit("")))
        .withColumn("service_clean", F.coalesce(F.col("service"), F.lit("unknown")))
    )

    return (
        df_clean
        .withColumn("fwd_pkt_len_mean", F.when(F.col("orig_pkts_clean") == 0, 0.0)
                    .otherwise(F.col("orig_bytes_clean") / F.col("orig_pkts_clean")))
        .withColumn("bwd_pkt_len_mean", F.when(F.col("resp_pkts_clean") == 0, 0.0)
                    .otherwise(F.col("resp_bytes_clean") / F.col("resp_pkts_clean")))
        .withColumn("pkt_len_mean", F.when((F.col("orig_pkts_clean") + F.col("resp_pkts_clean")) == 0, 0.0)
                    .otherwise((F.col("orig_bytes_clean") + F.col("resp_bytes_clean")) / (F.col("orig_pkts_clean") + F.col("resp_pkts_clean"))))
        .withColumn("down_up_ratio", F.when(F.col("orig_bytes_clean") == 0, 0.0)
                    .otherwise(F.col("resp_bytes_clean") / F.col("orig_bytes_clean")))
        .withColumn("flow_byts_s", F.when(F.col("duration_clean") <= 0, 0.0)
                    .otherwise((F.col("orig_bytes_clean") + F.col("resp_bytes_clean")) / F.col("duration_clean")))
        .withColumn("flow_pkts_s", F.when(F.col("duration_clean") <= 0, 0.0)
                    .otherwise((F.col("orig_pkts_clean") + F.col("resp_pkts_clean")) / F.col("duration_clean")))
        .withColumn("orig_to_resp_pkt_ratio", F.col("orig_pkts_clean") / (F.col("resp_pkts_clean") + F.lit(1.0)))
        .withColumn("is_conn_failed", F.when(F.col("conn_state").isin("S0", "REJ", "RSTO", "RSTRH", "SH"), 1).otherwise(0))
        .withColumn("syn_flag_cnt", F.when(F.col("history_clean").rlike("[Ss]"), 1).otherwise(0))
        .withColumn("fin_flag_cnt", F.when(F.col("history_clean").rlike("[Ff]"), 1).otherwise(0))
        .withColumn("rst_flag_cnt", F.when(F.col("history_clean").rlike("[Rr]"), 1).otherwise(0))
        .withColumn("ack_flag_cnt", F.when(F.col("history_clean").rlike("[Aa]"), 1).otherwise(0))
    )