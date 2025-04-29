import socket
import threading
from cryptography.fernet import Fernet

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

# Store active peers (socket: username)
peers = {}
message_registry = {}  # Track messages sent by each client

def generate_encryption_key():
    return Fernet.generate_key()

# Encrypt a message
def encrypt_message(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    fernet = Fernet(key)
    return fernet.encrypt(message)

# Decrypt a message
def decrypt_message(key, encrypted_message):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Handle incoming requests
# Only showing the modified parts of the server code - the rest remains the same

def handle_client(client_socket, client_address):
    try:
        username = client_socket.recv(2048).decode()
        peers[client_socket] = username
        print(f"{username} ({client_address}) connected.")

        client_socket.sendall("Connected to the server!".encode())
        filetransfer = False
        current_file_recipients = []  # Track recipients during file transfer
        client_socket.settimeout(None)

        while True:
            try:
                message = client_socket.recv(8192)
                try:
                    decoded_message = message.decode()
                    
                    if decoded_message.find("DELETE_MSG:")!=-1:
                        message_id = decoded_message.split(":")[1]
                        for peer_socket in peers.keys():
                            if peer_socket != client_socket:
                                peer_socket.sendall(f"DELETE_MSG:{message_id}".encode())
                        continue

                    if decoded_message.find("GET_PEERS")!=-1:
                        print("hello")
                        peer_list = "\n".join(peers.values())
                        client_socket.sendall(peer_list.encode())

                    if decoded_message.find("MSG_ID:")!=-1:
                        parts = decoded_message.split(":", 3)
                        message_id = parts[1]
                        
                        if parts[2] == "GROUP":
                            recipients, group_message = parts[3].split(":", 1)
                            recipient_list = [r.strip() for r in recipients.split(',')]
                            
                            # Send to specified recipients only
                            for peer_socket, peer_name in peers.items():
                                if peer_name in recipient_list and peer_socket != client_socket:
                                    peer_socket.sendall(f"[Group] {peers[client_socket]}: {group_message}".encode())
                            continue
                        else:
                            actual_message = parts[2]
                            # Handle broadcast message
                            for peer_socket in peers.keys():
                                if peer_socket != client_socket:
                                    peer_socket.sendall(f"{peers[client_socket]}: {actual_message}".encode())
                            continue

                    if decoded_message.startswith("GROUP_FILE:"):
                        # Format: "GROUP_FILE:recipient1,recipient2:filename"
                        _, recipients, filename = decoded_message.split(":", 2)
                        filetransfer = True
                        current_file_recipients = [r.strip() for r in recipients.split(',')]
                        
                        # Send file header to specified recipients
                        for peer_socket, peer_name in peers.items():
                            if peer_name in current_file_recipients:
                                peer_socket.sendall(f"FILE:{filename}".encode())
                    elif decoded_message.startswith("FILE:"):
                        filetransfer = True
                        current_file_recipients = []  # Empty list means broadcast
                        for peer_socket in peers.keys():
                            if peer_socket != client_socket:
                                peer_socket.sendall(message)
                    
                    elif decoded_message.startswith("FILE_DOWNLOADED:"):
                        _, filename = decoded_message.split(":", 1)
                        for peer_socket in peers.keys():
                            if peer_socket != client_socket:
                                peer_socket.sendall(f"{peers[client_socket]} downloaded file: {filename}".encode())
                    
                    elif filetransfer:
                        if current_file_recipients:
                            # Group file transfer
                            for peer_socket, peer_name in peers.items():
                                if peer_name in current_file_recipients:
                                    peer_socket.sendall(message)
                        else:
                            # Broadcast file transfer
                            for peer_socket in peers.keys():
                                if peer_socket != client_socket:
                                    peer_socket.sendall(message)
                        
                        if message == b"EOF":
                            filetransfer = False
                            current_file_recipients = []

                except UnicodeDecodeError:
                    # Handle binary data during file transfer
                    if filetransfer:
                        if current_file_recipients:
                            # Group file transfer
                            for peer_socket, peer_name in peers.items():
                                if peer_name in current_file_recipients:
                                    peer_socket.sendall(message)
                        else:
                            # Broadcast file transfer
                            for peer_socket in peers.keys():
                                if peer_socket != client_socket:
                                    peer_socket.sendall(message)
            except:
                break
    except:
        pass
    finally:
        if client_socket in peers:
            print(f"{peers[client_socket]} disconnected.")
            
            
            
            for peer_socket in peers.keys():
                if peer_socket != client_socket:
                   peer_socket.sendall((f"{peers[client_socket]} disconnected.").encode())
            
            del peers[client_socket]

        client_socket.close()

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server running on {HOST}:{PORT}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    server()