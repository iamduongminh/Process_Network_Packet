import pyspark.sql.functions as F

PRIVATE_IP_REGEX = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"

def build_dimensions(df_silver):
    dim_time = (
        df_silver
        .select(F.date_trunc("minute", F.col("event_time")).alias("time_key"))
        .filter(F.col("time_key").isNotNull())
        .distinct()
        .withColumn("date", F.to_date("time_key"))
        .withColumn("hour", F.hour("time_key"))
        .withColumn("minute", F.minute("time_key"))
        .withColumn("day_of_week", F.date_format("time_key", "EEEE"))
        .withColumn("is_weekend", F.dayofweek("time_key").isin(1, 7))
        .withColumn("hour_bucket", F.format_string("%02d:00 - %02d:59", F.hour("time_key"), F.hour("time_key")))
    )

    ports_union = (
        df_silver.select(F.col("orig_p").alias("port"))
        .union(df_silver.select(F.col("resp_p").alias("port")))
        .filter(F.col("port").isNotNull())
        .distinct()
    )
    dim_port = (
        ports_union
        .withColumn("port_category",
            F.when(F.col("port") <= 1023, "Well-Known (0-1023)")
             .when(F.col("port") <= 49151, "Registered (1024-49151)")
             .otherwise("Dynamic/Private (49152-65535)")
        )
        .withColumn("common_service",
            F.when(F.col("port") == 53, "DNS")
             .when(F.col("port") == 80, "HTTP")
             .when(F.col("port") == 443, "HTTPS / QUIC")
             .when(F.col("port") == 445, "SMB")
             .when(F.col("port") == 88, "Kerberos")
             .when(F.col("port") == 22, "SSH")
             .when(F.col("port") == 3389, "RDP")
             .otherwise("Other")
        )
    )

    dim_protocol = (
        df_silver
        .select("proto", "service")
        .distinct()
        .withColumn("is_encrypted", F.col("service").isin("ssl", "tls", "ssh", "quic"))
        .withColumn("osi_layer",
            F.when(F.col("service") != "unknown", "Application (L7)")
             .when(F.col("proto").isin("tcp", "udp"), "Transport (L4)")
             .otherwise("Network (L3)")
        )
    )

    return {"dim_time": dim_time, "dim_port": dim_port, "dim_protocol": dim_protocol}

def build_facts_by_direction(df_silver):
    df_tagged = (
        df_silver
        .withColumn("time_key", F.date_trunc("minute", F.col("event_time")))
        .withColumn("orig_is_local", F.col("orig_h").rlike(PRIVATE_IP_REGEX))
        .withColumn("resp_is_local", F.col("resp_h").rlike(PRIVATE_IP_REGEX))
        .withColumn("traffic_direction",
            F.when(F.col("orig_is_local") & F.col("resp_is_local"), "local")
             .when(F.col("orig_is_local") & (~F.col("resp_is_local")), "outbound")
             .when((~F.col("orig_is_local")) & F.col("resp_is_local"), "inbound")
             .otherwise("external")
        )
    )

    return {
        "fact_inbound": df_tagged.filter(F.col("traffic_direction") == "inbound"),
        "fact_outbound": df_tagged.filter(F.col("traffic_direction") == "outbound"),
        "fact_local": df_tagged.filter(F.col("traffic_direction") == "local"),
    }