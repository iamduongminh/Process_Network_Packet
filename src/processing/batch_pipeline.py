import os
import argparse
from pyspark.sql import functions as F

from configs.zeek_schemas import (
    ZEEK_FILTER_PATH, BRONZE_DIR, SILVER_DIR,
    GOLD_FEATURE_STORE_DIR, GOLD_DATA_MODEL_DIR, get_zeek_schemas
)
from src.utils.spark_session import get_spark_session
from src.ingestion.zeek.pcap_extractor import extract_pcap_to_bronze
from src.processing.transformations import cleaning, enrichment, windowing, modeling

def read_bronze_log(spark, log_path: str, schema):
    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
        df = spark.read.schema(schema).json(log_path)
    else:
        df = spark.read.schema(schema).json(spark.sparkContext.emptyRDD())
    return df.withColumn("event_time", F.to_timestamp(F.col("ts")))

def save_table(df, output_path: str, fmt: str):
    if fmt == "csv":
        df.coalesce(1).write.mode("overwrite").option("header", "true").csv(output_path)
    else:
        df.write.mode("overwrite").parquet(output_path)

def main():
    parser = argparse.ArgumentParser(description="NIDS Medallion Batch Pipeline")
    parser.add_argument("--pcap", type=str, required=True, help="Đường dẫn tới file .pcap")
    parser.add_argument("--format", type=str, choices=["csv", "parquet"], default="parquet", help="Định dạng lưu trữ")
    args = parser.parse_args()

    pcap_stem = os.path.splitext(os.path.basename(args.pcap))[0]

    # 1. TẦNG BRONZE: Chạy Zeek bóc tách PCAP
    bronze_path = os.path.join(BRONZE_DIR, pcap_stem)
    extract_pcap_to_bronze(args.pcap, bronze_path, ZEEK_FILTER_PATH)

    # 2. TẦNG SILVER: Đọc 8 log, làm sạch & hợp nhất
    spark = get_spark_session(f"NIDS_Batch_{pcap_stem}")
    spark.sparkContext.setLogLevel("WARN")
    schemas = get_zeek_schemas()

    print("[Silver] Đang hợp nhất 8 luồng dữ liệu...")
    logs = {
        name: read_bronze_log(spark, os.path.join(bronze_path, f"{name}.log"), schema)
        for name, schema in schemas.items()
    }
    logs["conn"] = cleaning.run(logs["conn"])
    df_silver = enrichment.run(logs).cache()

    silver_out = os.path.join(SILVER_DIR, pcap_stem, f"unified_flows_{args.format}")
    save_table(df_silver, silver_out, args.format)

    # 3. TẦNG GOLD - NHÁNH 1: FEATURE STORE (Phục vụ AI/ML)
    print("[Gold - Feature Store] Đang tạo đặc trưng hành vi & cửa sổ thời gian...")
    ml_drop_cols = ["uid", "orig_h", "resp_h", "proto", "service", "conn_state"]
    df_ml_flows = df_silver.drop(*ml_drop_cols)
    df_ml_windows = windowing.run(df_silver)

    fs_base = os.path.join(GOLD_FEATURE_STORE_DIR, pcap_stem)
    save_table(df_ml_flows, os.path.join(fs_base, f"flow_features_{args.format}"), args.format)
    save_table(df_ml_windows, os.path.join(fs_base, f"window_metrics_{args.format}"), args.format)

    # 4. TẦNG GOLD - NHÁNH 2: DATA MODEL (Star Schema phục vụ BI)
    print("[Gold - Data Model] Đang tách bảng Dimension & Fact...")
    dw_base = os.path.join(GOLD_DATA_MODEL_DIR, pcap_stem)
    for name, df_dim in modeling.build_dimensions(df_silver).items():
        save_table(df_dim, os.path.join(dw_base, f"{name}_{args.format}"), args.format)
    for name, df_fact in modeling.build_facts_by_direction(df_silver).items():
        save_table(df_fact, os.path.join(dw_base, f"{name}_{args.format}"), args.format)

    print(f"[SUCCESS] Hoàn tất xử lý {pcap_stem}: {df_silver.count()} phiên.")
    df_silver.unpersist()
    spark.stop()

if __name__ == "__main__":
    main()