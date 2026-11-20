import os
from pyspark.sql.types import (
    StructType, StructField, StringType, DoubleType,
    LongType, IntegerType, ArrayType, BooleanType
)

# Định vị gốc dự án Process_Network_Packet/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

ZEEK_FILTER_PATH = os.path.join(BASE_DIR, "src", "ingestion", "zeek", "zeek_filter.zeek")
BRONZE_DIR = os.path.join(BASE_DIR, "data", "lakehouse", "bronze")
SILVER_DIR = os.path.join(BASE_DIR, "data", "lakehouse", "silver")
GOLD_FEATURE_STORE_DIR = os.path.join(BASE_DIR, "data", "lakehouse", "gold", "feature_store")
GOLD_DATA_MODEL_DIR = os.path.join(BASE_DIR, "data", "lakehouse", "gold", "data_model")

def get_zeek_schemas():
    """Trả về static schema phẳng khớp chính xác với JSON log của Zeek"""
    id_fields = [
        StructField("id.orig_h", StringType(), True),
        StructField("id.orig_p", IntegerType(), True),
        StructField("id.resp_h", StringType(), True),
        StructField("id.resp_p", IntegerType(), True),
    ]

    return {
        "conn": StructType([
            StructField("ts", DoubleType(), True),
            StructField("uid", StringType(), True),
            *id_fields,
            StructField("proto", StringType(), True),
            StructField("service", StringType(), True),
            StructField("duration", DoubleType(), True),
            StructField("orig_bytes", LongType(), True),
            StructField("resp_bytes", LongType(), True),
            StructField("orig_pkts", LongType(), True),
            StructField("resp_pkts", LongType(), True),
            StructField("history", StringType(), True),
            StructField("conn_state", StringType(), True),
        ]),
        "dns": StructType([
            StructField("ts", DoubleType(), True),
            StructField("uid", StringType(), True),
            *id_fields,
            StructField("proto", StringType(), True),
            StructField("query", StringType(), True),
            StructField("qtype_name", StringType(), True),
            StructField("rcode_name", StringType(), True),
            StructField("answers", ArrayType(StringType()), True),
        ]),
        "http": StructType([
            StructField("ts", DoubleType(), True),
            StructField("uid", StringType(), True),
            *id_fields,
            StructField("method", StringType(), True),
            StructField("host", StringType(), True),
            StructField("uri", StringType(), True),
            StructField("user_agent", StringType(), True),
            StructField("status_code", IntegerType(), True),
        ]),
        "ssl": StructType([
            StructField("ts", DoubleType(), True),
            StructField("uid", StringType(), True),
            *id_fields,
            StructField("version", StringType(), True),
            StructField("cipher", StringType(), True),
            StructField("server_name", StringType(), True),
        ]),
    }