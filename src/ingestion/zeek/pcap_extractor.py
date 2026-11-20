import os
import shutil
import subprocess

def extract_pcap_to_bronze(pcap_path: str, bronze_output_dir: str, zeek_script_path: str) -> str:
    """Chạy Zeek trích xuất 8 luồng JSON log từ file PCAP bất kỳ vào tầng Bronze"""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"Không tìm thấy file PCAP: {pcap_path}")

    if os.path.exists(bronze_output_dir):
        shutil.rmtree(bronze_output_dir)
    os.makedirs(bronze_output_dir, exist_ok=True)

    cmd = ["zeek", "-r", os.path.abspath(pcap_path), os.path.abspath(zeek_script_path)]
    print(f"[Bronze] Đang bóc tách gói tin bằng Zeek: {os.path.basename(pcap_path)} ...")
    subprocess.run(cmd, cwd=bronze_output_dir, check=True)
    return bronze_output_dir