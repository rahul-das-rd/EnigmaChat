import os
import platform
import socket
import logging
import argparse
import threading
from datetime import datetime
import hashlib
import hmac
from colorama import init, Fore, Style
import base64
import cryptography.fernet
from cryptography.fernet import Fernet

# Initialize colorama for colored output
init(autoreset=True)

# Dictionary to store connected clients
clients = {}
clients_lock = threading.Lock()

# Function to set up logging
def log_setup(loglevel, logfile):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {loglevel}")

    logging.basicConfig(level=numeric_level,
                        format="%(asctime)s [%(levelname)s] - %(message)s",
                        handlers=[logging.FileHandler(logfile),
                                  logging.StreamHandler()])

# Thread class to handle each client connection
class ClientHandler(threading.Thread):
    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
        self.username = None

    # Function to run the thread
    def run(self):
        global clients

        # Ask for and validate the username
        while True:
            try:
                # Prompt the client for username
                encrypted_prompt = cipher.encrypt("Enter your username: ".encode('utf-8'))
                self.client_socket.send(encrypted_prompt)
                encrypted_username = self.client_socket.recv(1024)
                username = cipher.decrypt(encrypted_username).decode('utf-8').strip()

                # Validate username uniqueness
                with clients_lock:
                    if username in clients or not username:
                        encrypted_error_msg = cipher.encrypt(
                            "This username is already taken or invalid. Please enter a different name.".encode('utf-8')
                        )
                        self.client_socket.send(encrypted_error_msg)
                        continue
                    else:
                        self.username = username
                        clients[self.username] = self.client_socket
                        encrypted_success_msg = cipher.encrypt("Username set successfully.".encode('utf-8'))
                        self.client_socket.send(encrypted_success_msg)
                        break
            except cryptography.fernet.InvalidToken:
                print(Fore.RED + f"Error with client: The encryption key is invalid or data is corrupted.")
                logging.info("Error with client: The encryption key is invalid or data is corrupted")
                continue
            except OSError as e:
                print(f"Error: {e}")
                logging.info(f"Error: {e}")
            except BrokenPipeError as e:
                print(f"An unknown error occurred: {e}")
                logging.info(f"An unknown error occurred: {e}")
            return

        # Process messages
        try:
            while True:
                encrypted_message = self.client_socket.recv(1024)
                message = cipher.decrypt(encrypted_message).decode('utf-8')

                # Handle special commands
                if message == "/userlist":
                    with clients_lock:
                        userlist = "\n".join([f"\t{i + 1}) {user}" for i, user in enumerate(clients.keys())])
                        encrypted_response = cipher.encrypt(f"Connected Users:\n{userlist}".encode('utf-8'))
                        self.client_socket.send(encrypted_response)
                        continue
                if message == "/help":
                    response = Fore.BLUE + "Help Menu:\n" \
                                          "\t/help                           -> Help Menu\n" \
                                          "\t/exit                           -> Exit the program.\n" \
                                          "\t/clear                          -> Clear the chat screen.\n" \
                                          "\t/userlist                       -> View the list of connected users.\n" \
                                          "\t/dm [user] [message]            -> Send a direct message to a user.\n" \
                                          "\t/changeuser [new_username]      -> Change your username.\n"
                    encrypted_response = cipher.encrypt(response.encode('utf-8'))
                    self.client_socket.send(encrypted_response)
                    continue
                if message.startswith("/changeuser "):
                    _, new_username = message.split()
                    with clients_lock:
                        if new_username in clients:
                            encrypted_error = cipher.encrypt(
                                "This username is already taken. Please choose another one.".encode('utf-8'))
                            self.client_socket.send(encrypted_error)
                        else:
                            del clients[self.username]
                            self.username = new_username
                            clients[self.username] = self.client_socket
                            encrypted_success = cipher.encrypt(f"Username changed to {new_username}.".encode('utf-8'))
                            self.client_socket.send(encrypted_success)
                    continue
                if message.startswith("/dm "):
                    _, recipient, *dm_msg_parts = message.split()
                    dm_message = " ".join(dm_msg_parts)
                    with clients_lock:
                        if recipient in clients:
                            clients[recipient].send(cipher.encrypt(f"[DM from {self.username}] {dm_message}".encode('utf-8')))
                            self.client_socket.send(cipher.encrypt(f"[DM to {recipient}] {dm_message}".encode('utf-8')))
                        else:
                            encrypted_error = cipher.encrypt("Specified user not found.".encode('utf-8'))
                            self.client_socket.send(encrypted_error)
                    continue

                # Perform proof of work before broadcasting the message
                block = self.createBlock(message)
                mined_block = self.mineBlock(block)
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                broadcast_message = f"[{current_time}] {self.username}: {message}"
                encrypted_broadcast = cipher.encrypt(broadcast_message.encode('utf-8'))
                with clients_lock:
                    for usr, client in clients.items():
                        if usr != self.username:
                            client.send(encrypted_broadcast)
        except:
            pass

        # Cleanup when the client exits
        with clients_lock:
            del clients[self.username]
            logging.info(f"The user left: {self.username}")
        self.client_socket.close()

    # Function to create a block containing the transaction data
    def createBlock(self, transaction):
        block = {
            'transaction': transaction,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return block

    # Function to perform proof of work or any equivalent mining process
    def mineBlock(self, block):
        # Set the difficulty level for proof of work
        difficulty = 4  # Number of leading zeros required in the hash

        # Perform proof of work
        while True:
            nonce = os.urandom(4)  # Random nonce value
            nonce_hex = nonce.hex()  # Convert nonce to hexadecimal string
            block_hash = hashlib.sha256(str(block).encode() + nonce).hexdigest()  # Calculate hash with nonce
            if block_hash.startswith('0' * difficulty):
                # Found a valid hash satisfying the difficulty condition
                mined_block = {
                    'block': block,
                    'nonce': nonce_hex
                }
                return mined_block

    def viewUser(self):
        try:
            # Placeholder for retrieving and displaying user's transaction history
            with clients_lock:
                print(f"Viewing all successful transactions for user: {self.username}")
                for transaction in self.transaction_history:
                    print(transaction)  # Modify this to display transaction details appropriately
        except cryptography.fernet.InvalidToken:
            print(Fore.RED + "Error: The encryption key is invalid or data is corrupted.")
            return False

    def verifyTransaction(self, transaction):
        # Implement HMAC verification for the transaction
        secret_key = b'my_secret_key'
        message = transaction.encode('utf-8')
        digest = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
        # Assume the digest is verified against some known value or condition
        return True

def start_server(host, port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        host_ip, host_port = server_socket.getsockname()
        server_socket.listen(5)
        print("Server started. Waiting for clients...")
        print(f"{Fore.YELLOW}Host information: {Style.RESET_ALL}{host_ip}:{host_port}")
        logging.info(f"Server started on {host_ip}:{host_port}")

        while True:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client_socket, client_address = server_socket.accept()
            print(f"[{current_time}] {client_address} Connected.")
            logging.info(f"Accepted connection from {client_address}")
            handler = ClientHandler(client_socket)
            handler.start()
    except cryptography.fernet.InvalidToken:
        print(f"{Fore.RED}Incorrect Key:{Style.RESET_ALL} [{current_time}] {client_address}")
        logging.error(f"Invalid token for {client_address}")
        pass
    except OSError as e:
        print(f"An error occurred while starting the server {e}")
        logging.error(f"An error occurred: {e}")
    except KeyboardInterrupt:
        print("Program terminated.....")
        logging.info("Server was terminated by keyboard interrupt")

# Parse command line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the chat server.")
    parser.add_argument("--host", default="0.0.0.0", help="The IP address to bind the server to. (Default=0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="The port number to bind the server to. (Default=12345)")
    parser.add_argument("--key", default="mysecretpassword", help="The secret key for encryption. (Default=mysecretpassword)")
    parser.add_argument("--loglevel", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (Default: INFO)")
    parser.add_argument("--logfile", default="server.log", help="Set the log file name. (Default: server.log)")
    args = parser.parse_args()

    # Set up encryption key
    password = args.key.encode()
    key = hashlib.sha256(password).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    cipher = Fernet(fernet_key)

    # Set up logging
    log_setup(args.loglevel, args.logfile)

    # Start the server
    start_server(args.host, args.port)
