import socket
import time
import threading

HOST = "127.0.0.1"
PORT = 5000


# ----------------------------
# SHARED STATE (no classes)
# ----------------------------

state = {
    "conn": None,
    "server_sock": None,
    "ready": threading.Event()
}


# ----------------------------
# SERVER THREAD
# ----------------------------

def server_loop():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)

    print("[SERVER] Listening...")

    conn, addr = s.accept()
    print(f"[SERVER] Connection from {addr}")

    # store globally
    state["conn"] = conn
    state["server_sock"] = s

    # signal main thread
    state["ready"].set()

    # keep alive so monitor catches it
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            time.sleep(0.1)
    except:
        pass


# ----------------------------
# CLIENT THREAD
# ----------------------------

def client_loop(duration=120):
    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("[CLIENT] Connecting...")
    sock.connect((HOST, PORT))

    print("[CLIENT] Connected. Holding...")

    start = time.time()
    while time.time() - start < duration:
        try:
            sock.send(b"ping")
            time.sleep(2)
        except:
            break

    print("[CLIENT] Closing...")
    sock.close()
    print("[CLIENT] Closed")


# ----------------------------
# PUBLIC ENTRY POINT
# ----------------------------

def run_test():
    """
    Starts server + client in background threads.
    Does NOT block main program.
    """

    # reset state every run
    state["conn"] = None
    state["server_sock"] = None
    state["ready"].clear()

    # start server
    threading.Thread(target=server_loop, daemon=True).start()

    # start client
    threading.Thread(target=client_loop, daemon=True).start()

    # DO NOT block — main decides when to wait
    print("[TEST] Entity server started in background")

    return state


# ----------------------------
# SAFE CLOSE FUNCTION
# ----------------------------

def close_connection(conn, server_sock, delay=5):
    print("[CLOSER] Preparing shutdown...")

    time.sleep(delay)

    try:
        if conn:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
    except:
        pass

    try:
        if server_sock:
            server_sock.close()
    except:
        pass

    print("[CLOSER] Closed all sockets")