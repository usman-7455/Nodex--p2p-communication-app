import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog,ttk

import os
import time
from tkinter import messagebox
from cryptography.fernet import Fernet

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345


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

class EmojiPicker(tk.Toplevel):
    def __init__(self, parent, message_input):
        super().__init__(parent)
        self.message_input = message_input
        self.title("Emoji Picker")
        self.geometry("300x200")
        
        # Common emojis - you can add more
        self.emojis = [
            "😊", "😂", "❤️", "👍", "😎",
            "🎉", "✨", "🌟", "💡", "📌",
            "🎵", "🎮", "📱", "💻", "📚",
            "👋", "🤝", "👀", "💭", "💬"
        ]
        
        self.create_emoji_buttons()

    def create_emoji_buttons(self):
        frame = ttk.Frame(self)
        frame.pack(padx=5, pady=5, expand=True)
        
        row = 0
        col = 0
        for emoji in self.emojis:
            btn = ttk.Button(
                frame,
                text=emoji,
                width=3,
                command=lambda e=emoji: self.insert_emoji(e)
            )
            btn.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if col > 4:  # 5 emojis per row
                col = 0
                row += 1

    def insert_emoji(self, emoji):
        current_position = self.message_input.index(tk.INSERT)
        self.message_input.insert(current_position, emoji)


class ChatClient:

    def __init__(self, root):
        self.root = root
        self.root.title("P2P Chat Client")
        self.root.geometry("500x600")
        self.username = None
        self.password = None
        self.client_socket = None
        self.message_ids = {}
        # Show login/signup dialog on initialization
        self.show_login_signup_dialog()

    def signup(self):
        # Get username
        self.username = simpledialog.askstring("Username", "Enter your username:")
        if not self.username:
            messagebox.showerror("Error", "Username is required!")
            return

        # Check if username already exists
        try:
            with open('peer_login.txt', 'r') as file:
                for line in file:
                    stored_username, _ = line.strip().split(':')
                    if stored_username == self.username:
                        messagebox.showerror("Signup Error", "Username is already in use!")
                        return
        except FileNotFoundError:
            # If the file does not exist, we can proceed to create a new user
            pass

        # Get password
        self.password = simpledialog.askstring("Password", "Enter your password:", show='*')
        if not self.password:
            messagebox.showerror("Error", "Password is required!")
            return

        try:
            with open('peer_login.txt', 'a') as file:
                file.write(f"{self.username}:{self.password}\n")
            messagebox.showinfo("Success", "Account created successfully!")
            self.login_and_connect()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credentials: {e}")

    def login(self):
        # Get username
        self.username = simpledialog.askstring("Username", "Enter your username:")
        if not self.username:
            messagebox.showerror("Error", "Username is required!")
            return

        # Get password
        self.password = simpledialog.askstring("Password", "Enter your password:", show='*')
        if not self.password:
            messagebox.showerror("Error", "Password is required!")
            return

        # Verify credentials
        try:
            with open('peer_login.txt', 'r') as file:
                for line in file:
                    stored_username, stored_password = line.strip().split(':')
                    if stored_username == self.username:
                        if stored_password == self.password:
                            self.login_and_connect()
                            return
                        else:
                            messagebox.showerror("Login Error", "Incorrect password!")
                            return
                
                # If loop completes without finding username
                messagebox.showerror("Login Error", "Username not found!")
        except FileNotFoundError:
            messagebox.showerror("Error", "No registered users. Please sign up first.")

    def login_and_connect(self):
        # Connect to the server
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            self.client_socket.sendall(self.username.encode())

            # Update window title
            self.root.title(f"{self.username}")

            # Clear any existing widgets
            for widget in self.root.winfo_children():
                widget.destroy()

            # Layout
            self.chat_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
            self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.chat_display.config(state=tk.DISABLED)

            # Frame for input fields
            self.input_frame = tk.Frame(self.root)
            self.input_frame.pack(padx=10, pady=5, fill=tk.X)
                  # Add emoji picker button
           

            # Message input field
            self.message_input = tk.Entry(self.input_frame)
            self.message_input.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
            self.message_input.bind("<Return>", self.send_message)

            # Username field for private messaging
            self.recipient_label = tk.Label(self.input_frame, text="To (empty for broadcast):")
            self.recipient_label.pack(side=tk.LEFT, padx=2)

            self.recipient_input = tk.Entry(self.input_frame, width=15)
            self.recipient_input.pack(side=tk.LEFT, padx=2)
            #emoji button
            self.emoji_button = tk.Button(
                self.input_frame,
                text="😊",
                command=self.show_emoji_picker,
                width=3
            )
            self.emoji_button.pack(side=tk.LEFT, padx=2)

            self.file_button = tk.Button(self.root, text="Send File", command=self.send_file)
            self.file_button.pack(pady=5)

            # Receive messages thread
            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to the server: {e}")
            self.show_login_signup_dialog()
            
    def show_emoji_picker(self):
        EmojiPicker(self.root, self.message_input)

    def show_login_signup_dialog(self):
        # Create a new window for login/signup options
        dialog = tk.Toplevel(self.root)
        dialog.title("Login or Signup")
        dialog.geometry("300x150")

        # Login button
        login_button = tk.Button(dialog, text="Login", command=self.login)
        login_button.pack(pady=20)

        # Signup button
        signup_button = tk.Button(dialog, text="Signup", command=self.signup)
        signup_button.pack(pady=20)

        # Center the dialog on the main window
        dialog.transient(self.root)  # Make the dialog stay on top of the main window
        dialog.grab_set()  # Disable interaction with the main window until the dialog is closed

    def add_message(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def send_message(self, event=None):
        message = self.message_input.get().strip()
        recipients = self.recipient_input.get().strip()

        if message:
            try:
                # Generate a unique message ID
                message_id = f"{int(time.time()*1000)}"

                # Split recipients by comma and remove whitespace
                recipient_list = [r.strip() for r in recipients.split(',')] if recipients else []

                # Format: "MSG_ID:message_id:GROUP:recipient1,recipient2:message" for group messages
                # or "MSG_ID:message_id:message" for broadcast
                if recipient_list:
                    formatted_message = f"MSG_ID:{message_id}:GROUP:{','.join(recipient_list)}:{message}"
                    recipients_str = ', '.join(recipient_list)
                    self.add_message(f"[Private to {recipients_str}] You: {message}", message_id)
                else:
                    formatted_message = f"MSG_ID:{message_id}:{message}"
                    self.add_message(f"[Broadcast] You: {message}", message_id)

                self.client_socket.sendall(formatted_message.encode())
                self.message_input.delete(0, tk.END)
            except:
                self.add_message("Failed to send the message.")
                self.client_socket.close()
                self.root.destroy()
    def add_message(self, message, message_id=None):
        self.chat_display.config(state=tk.NORMAL)
        
        # Create a frame to hold the message and delete button
        message_frame = tk.Frame(self.chat_display)
        
        # Add message text
        message_label = tk.Label(message_frame, text=message, anchor='w', justify=tk.LEFT, wraplength=450)
        message_label.pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Add delete button if message_id is provided
        if message_id:
            delete_btn = tk.Button(
                message_frame, 
                text='🗑️', 
                command=lambda mid=message_id: self.delete_message(mid),
                width=3
            )
            delete_btn.pack(side=tk.RIGHT)
            
            # Store message reference
            self.message_ids[message_id] = {'frame': message_frame, 'label': message_label}

        # Insert the frame into the chat display
        self.chat_display.window_create(tk.END, window=message_frame)
        self.chat_display.insert(tk.END, "\n")
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def send_file_download_notification(self, filename):
        try:
            self.client_socket.sendall(f"FILE_DOWNLOADED:{filename}".encode())
        except Exception as e:
            self.add_message(f"Failed to send file download notification: {e}")

    def delete_message(self, message_id):
        if message_id in self.message_ids:
            # Remove from display
            message_frame = self.message_ids[message_id]['frame']
            message_frame.destroy()
            del self.message_ids[message_id]

            # Send delete request to server
            try:
                self.client_socket.sendall(f"DELETE_MSG:{message_id}".encode())
            except Exception as e:
                print(f"Failed to send delete request: {e}")

    def receive_messages(self):
        file_receiving = False
        file_name = ""
        file_content = b""

        while True:
            try:
                message = self.client_socket.recv(8192)

                try:
                    decoded_message = message.decode()


                    # Handle message deletion
                    if decoded_message.startswith("DELETE_MSG:"):
                        message_id = decoded_message.split(":")[1]
                        if message_id in self.message_ids:
                            message_frame = self.message_ids[message_id]['frame']
                            message_frame.destroy()
                            del self.message_ids[message_id]
                        continue

                    if not file_receiving and not decoded_message.startswith("FILE:"):
                        self.add_message(decoded_message)
                        continue
                except UnicodeDecodeError:
                   pass 

                if not file_receiving and b"FILE:" in message:
                    file_name = message.decode().split("FILE:")[1].strip()
                    self.add_message(f"Receiving file: {file_name}")
                    file_receiving = True
                    file_content = b""
                    continue

                if file_receiving:
                    if b"EOF" in message:
                        last_chunk = message.split(b"EOF")[0]
                        file_content += last_chunk

                        save_path = filedialog.asksaveasfilename(
                            initialfile=file_name,
                            title="Save File As",
                            defaultextension="",
                            filetypes=[("All Files", "*.*")]
                        )

                        if save_path:
                            try:
                                with open(save_path, "wb") as file:
                                    file.write(file_content)
                                self.add_message(f"File saved successfully: {save_path}")
                                self.add_message(f"File size: {len(file_content)} bytes")

                                self.send_file_download_notification(file_name)

                            except Exception as save_error:
                                self.add_message(f"Error saving file: {save_error}")
                        else:
                            self.add_message(f"File '{file_name}' was not saved.")

                        file_receiving = False
                        file_name = ""
                        file_content = b""
                        continue
                    else:
                        file_content += message

            except Exception as e:
                self.add_message(f"Lost connection to server: {e}")
                break
    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                file_name = os.path.basename(file_path)
                recipients = self.recipient_input.get().strip()
                recipient_list = [r.strip() for r in recipients.split(',')] if recipients else []
                
                self.client_socket.settimeout(None)

                if recipient_list:
                    self.client_socket.sendall(f"GROUP_FILE:{','.join(recipient_list)}:{file_name}".encode())
                    recipients_str = ', '.join(recipient_list)
                    self.add_message(f"[Private to {recipients_str}] Sending file: {file_name}")
                else:
                    self.client_socket.sendall(f"FILE:{file_name}".encode())
                    self.add_message(f"[Broadcast] Sending file: {file_name}")

                with open(file_path, "rb") as file:
                    file_size = os.path.getsize(file_path)
                    total_sent = 0
                    for chunk in iter(lambda: file.read(8192), b''):
                        try:
                            self.client_socket.sendall(chunk)
                            time.sleep(0.01)
                            total_sent += len(chunk)
                            self.add_message(f"Sent {total_sent}/{file_size} bytes")
                        except Exception as chunk_error:
                            self.add_message(f"Error sending chunk: {chunk_error}")
                            break

                self.client_socket.sendall(b"EOF")
                self.add_message(f"File '{file_name}' sent completely.")

            except BrokenPipeError:
                self.add_message("Error: Connection to server lost.")
            except Exception as e:
                self.add_message(f"Failed to send the file: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()