from pyspark.sql import SparkSession

def get_spark_session(app_name: str = "NIDS_Batch_Pipeline") -> SparkSession:
    return (
        SparkSession.builder
        .appName(app_name)
        .master("local[*]")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )