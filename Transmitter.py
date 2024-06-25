import pyudev
import time
import threading
import subprocess
import socket

udp_ip = "127.0.0.1"  # The IP address of the RX device (localhost for testing)
udp_port = 5005       # The port to send data to

payload = "12345678"

print("Payload (data to be sent):", payload)

# Convert payload to a string to find its length
payload_length = len(payload)
print("Length of payload:", payload_length)
print(" ")

stop_monitoring = threading.Event()
password = None

def usb_event_observer(action, device):
    global password
    if action == 'add' and ('usb' in device.get('ID_BUS', '') or 'usb' in device.device_path):
        print(f" ")
        print(f" ")
        print("USB device detected!")
        password = print_block_devices(payload)
    elif action == 'remove' and ('usb' in device.get('ID_BUS', '') or 'usb' in device.device_path):
        print(f" ")
        print(f" ")
        print("USB device removed. Exiting...")
        stop_monitoring.set()

def get_block_devices():
    try:
        output = subprocess.check_output(["lsblk"], encoding="utf-8")
        time.sleep(3)
        return [line.split()[-1] for line in output.split('\n') if '/media' in line]
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []

def print_directory_contents(directory):
    global password
    try:
        # print(f"Contents of {directory}:")
        ls_output = subprocess.check_output(["ls", directory], encoding="utf-8")
        # print(ls_output)
        txt_files = [file for file in ls_output.split() if file.endswith('.txt')]
        for txt_file in txt_files:
            with open(f"{directory}/{txt_file}", "r") as file:
                password = file.read().strip()
                print(f" ")
                print(f" ")
                print(f"Password read from USB: {password}")
                # print(file_contents)
        return password
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

def generate_data_packet(password, payload):
    payload_length = len(payload)
    data_packet = f"{password}{payload_length}{payload}"
    return data_packet

def xor_multiply(password, data_packet):
    password_bytes = password.encode('utf-8')
    data_packet_bytes = data_packet.encode('utf-8')
    result_bytes = bytes(x ^ y for x, y in zip(data_packet_bytes, password_bytes * (len(data_packet_bytes) // len(password_bytes) + 1)))
    result = result_bytes.decode('utf-8')
    return result

def print_block_devices(payload):
    global password
    media_directories = get_block_devices()
    for directory in media_directories:
        password = print_directory_contents(directory)
        if password:
            data_packet = generate_data_packet(password, payload)
            print("Generated data packet:", data_packet)
            print(f" ")
            print(f" ")
            encoded_data = xor_multiply(password, data_packet)
            print("Encoded_data for transmission:", encoded_data)
            print(f" ")
            print(f" ")
            send_udp_data(encoded_data)

            # # XOR multiply again to retrieve original data packet
            # decoded_data = xor_multiply(password, encoded_data)
            # print("Data decoded at receiver:", decoded_data)
            # print(f" ")
            # print(f" ")


            # print("Data parsed at receiver...")
            # password, payload_length, payload = split_data_packet(decoded_data, len(password))
            # print("Password:", password)
            # print("Payload Length:", payload_length)
            # print("Payload:", payload)
            return password

def send_udp_data(encoded_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(encoded_data.encode('utf-8'), (udp_ip, udp_port))
    print(f"Data sent to {udp_ip}:{udp_port}")

# def split_data_packet(data_packet, password_length):
#     # Extracting password (first part)
#     password = data_packet[:password_length]
    
#     # Extracting payload length (second part)
#     payload_length = int(data_packet[password_length: password_length + 1])
    
#     # Extracting payload (last part)
#     payload = data_packet[password_length + 1:]
    
#     return password, payload_length, payload

def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')
    observer = pyudev.MonitorObserver(monitor, usb_event_observer, name='usb-observer')
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
    monitor_usb()
