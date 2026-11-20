import json
import time
from confluent_kafka import Producer

# Cấu hình kết nối tới Kafka Docker
conf = {'bootstrap.servers': 'localhost:9092'}
producer = Producer(conf)

def delivery_report(err, msg):
    if err is not None:
        print(f"Lỗi gửi tin: {err}")

def tail_and_publish(file_path, topic_name):
    print(f"Đang đẩy dữ liệu từ {file_path} vào topic '{topic_name}'...")
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    # Đẩy từng dòng JSON vào Kafka topic
                    producer.produce(topic_name, line.encode('utf-8'), callback=delivery_report)
                    producer.poll(0)
                    time.sleep(0.01) # Giả lập luồng streaming trễ 10ms
            producer.flush()
            print(f"Hoàn tất đẩy {topic_name}.")
    except FileNotFoundError:
        print(f"Chưa tìm thấy file {file_path}. Hãy chạy Zeek trước.")

if __name__ == '__main__':
    log_dir = "../zeek_raw"
    # Giả lập đọc tuần tự 4 file và đẩy vào 4 topic khác nhau
    tail_and_publish(f"{log_dir}/conn.log", "zeek_conn")
    tail_and_publish(f"{log_dir}/dns.log", "zeek_dns")
    tail_and_publish(f"{log_dir}/http.log", "zeek_http")
    tail_and_publish(f"{log_dir}/ssl.log", "zeek_ssl")