# rx_script.py

import pyudev
import time
import threading
import subprocess
import socket

udp_ip = "0.0.0.0"  # Listen on all available interfaces
udp_port = 5005     # The port to receive data on

stop_monitoring = threading.Event()
password = None

def usb_event_handler(action, device):
    global password
    if action == 'add' and ('usb' in device.get('ID_BUS', '') or 'usb' in device.device_path):
        print(f" ")
        print(f" ")
        print("USB device detected!")
        listen_udp_data()
    elif action == 'remove' and ('usb' in device.get('ID_BUS', '') or 'usb' in device.device_path):
        print(f" ")
        print(f" ")
        print("USB device removed. Exiting...")
        stop_monitoring.set()

def list_block_devices():
    try:
        output = subprocess.check_output(["lsblk"], encoding="utf-8")
        return [line.split()[-1] for line in output.split('\n') if '/media' in line]
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []

def read_password_from_directory(directory):
    global password
    try:
        ls_output = subprocess.check_output(["ls", directory], encoding="utf-8")
        txt_files = [file for file in ls_output.split() if file.endswith('.txt')]
        for txt_file in txt_files:
            with open(f"{directory}/{txt_file}", "r") as file:
                password = file.read().strip()
                print(f" ")
                print(f" ")
                print(f"Password read from USB: {password}")
        return password
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

def xor_operation(password, data_packet):
    password_bytes = password.encode('utf-8')
    data_packet_bytes = data_packet.encode('utf-8')
    result_bytes = bytes(x ^ y for x, y in zip(data_packet_bytes, password_bytes * (len(data_packet_bytes) // len(password_bytes) + 1)))
    result = result_bytes.decode('utf-8')
    return result

def parse_data_packet(data_packet, password_length):
    # Extracting password (first part)
    password = data_packet[:password_length]
    
    # Extracting payload length (second part)
    payload_length = int(data_packet[password_length: password_length + 1])
    
    # Extracting payload (last part)
    payload = data_packet[password_length + 1:]
    
    return password, payload_length, payload

def process_block_devices(encoded_data):
    global password
    media_directories = list_block_devices()
    for directory in media_directories:
        password = read_password_from_directory(directory)
        if password:
            decoded_data = xor_operation(password, encoded_data)
            print("Data decoded at receiver:", decoded_data)
            print(f" ")
            print(f" ")

            print("Data parsed at receiver...")
            password, payload_length, payload = parse_data_packet(decoded_data, len(password))
            print("Password:", password)
            print("Payload Length:", payload_length)
            print("Payload:", payload)
            return decoded_data

def listen_udp_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((udp_ip, udp_port))
    print(f"Listening for UDP data on port {udp_port}...")
    data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
    encoded_data = data.decode('utf-8')
    print(f"Received encoded data from {addr}: {encoded_data}")
    process_block_devices(encoded_data)

def monitor_usb_devices():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')
    observer = pyudev.MonitorObserver(monitor, usb_event_handler, name='usb-observer')
    observer.start()
    print("Waiting for USB. Press Ctrl+C to exit...")
    try:
        while not stop_monitoring.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("Device stopped by user!")
    finally:
        observer.stop()

if __name__ == "__main__":
    monitor_usb_devices()
