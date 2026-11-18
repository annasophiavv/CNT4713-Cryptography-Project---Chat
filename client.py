# CNT4713 Cryptography Project - Chat
# Client implementation
import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ------------------------------------------------------------

KEY_SIZE = 2048
BLOCK_SIZE = KEY_SIZE // 8  

SEND_HASH = hashes.SHA256  


def make_oaep(hash_type):
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hash_type()),
        algorithm=hash_type(),
        label=None
    )


# padding used when we encrypt
OAEP = make_oaep(SEND_HASH)

CHUNK_SIZE = BLOCK_SIZE - 2 * SEND_HASH.digest_size - 2

DECRYPT_PADDINGS = [make_oaep(hashes.SHA256), make_oaep(hashes.SHA1)]

private_key = None
public_pem = None
server_public_key = None

# stores responses from server
command_response = None

# tells main thread when a response is ready
response_event = threading.Event()

# username to log in with
pending_login = None


# encrypt text with a public key, one chunk at a time
def encrypt_message(text, key):
    data = text.encode()
    ciphertext = b""

    for i in range(0, len(data), CHUNK_SIZE):
        ciphertext += key.encrypt(data[i:i + CHUNK_SIZE], OAEP)

    return ciphertext


# decrypt with our private key
def decrypt_message(ciphertext):
    data = b""

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]

        for pad in DECRYPT_PADDINGS:
            try:
                data += private_key.decrypt(block, pad)
                break
            except ValueError:
                continue
        else:
            raise ValueError("could not decrypt block")

    return data


# ------------------------------------------------------------

def send_encrypted(sock, text):
    global command_response

    ciphertext = encrypt_message(text, server_public_key)

    try:
        sock.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)

    except (ConnectionError, OSError):
        command_response = "500\n\n"
        response_event.set()


# keep calling recv until we have exactly n bytes
def recv_exact(sock, n):
    data = b""

    while len(data) < n:
        chunk = sock.recv(n - len(data))

        # connection closed
        if not chunk:
            return None

        data += chunk

    return data


# read one full encrypted message from the socket
def recv_encrypted(sock):
    header = recv_exact(sock, 4)

    if header is None:
        return None

    length = struct.unpack("!I", header)[0]
    return recv_exact(sock, length)


# listen for messages coming from server through the data socket
def receive_messages(data_socket):
    global command_response, pending_login

    # continue listening until the connection closes/error happens
    while True:
        try:
            ciphertext = recv_encrypted(data_socket)

            if ciphertext is None:
                break

            try:
                message = decrypt_message(ciphertext).decode()
            except (ValueError, UnicodeDecodeError):
                continue

            # Broadcast message
            if message.startswith("200\n\nBroadcast\n"):
                parts = message.split("\n", 4)

                if len(parts) >= 5:
                    print("Received encrypted message")
                    print(parts[0] + " status code received.")
                    print("Broadcast message from", parts[3] + ":", parts[4])

            # Private message
            elif message.startswith("200\n\nPrivate\n"):
                parts = message.split("\n", 4)

                if len(parts) >= 5:
                    print("Received encrypted message")
                    print(parts[0] + " status code received.")
                    print(parts[3] + ":", parts[4])

            # Join notification
            elif message.startswith("200\n\njoin\n"):
                joined_user = message.split("\n", 3)[3].strip()

                if pending_login is not None and joined_user == pending_login:
                    pending_login = None
                    print("Received encrypted message")
                    command_response = message
                    response_event.set()

            # Logout notification
            elif message.startswith("200\n\nLogout\n"):
                pass

            # Response to a command 
            elif is_status_message(message):
                pending_login = None
                print("Received encrypted message")
                command_response = message
                response_event.set()

            else:
                pass

        except (ConnectionError, OSError):
            break

    # connection is gone
    if not response_event.is_set():
        command_response = "500\n\n"
        response_event.set()


# wait until receiver thread gets a normal command response
def wait_for_response():
    global command_response

    # pause thread until response_event.set() is called
    if not response_event.wait(timeout=10):
        return "500\n\n"

    response = command_response

    command_response = None
    response_event.clear()

    return response


def is_status_message(message):
    return (
        len(message) >= 3
        and message[:3].isdigit()
        and (len(message) == 3 or message[3] == "\n")
    )


# getting the status code from server response
def get_status(response):
    return response.split("\n", 1)[0].strip()


# read the plaintext connect response until the whole public key has arrived
def recv_connect_response(sock):
    data = b""

    while b"-----END PUBLIC KEY-----" not in data:
        chunk = sock.recv(4096)

        # server closed early or sent an error with no key
        if not chunk:
            break

        data += chunk

        if data.startswith(b"500"):
            break

    return data.decode()


# deals w user input/sends commands to server
def main():
    global private_key, public_pem, server_public_key, pending_login

    print("Starting client...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE
    )

    # public key as PEM text so it can be sent in the login message
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    control_socket = None
    data_socket = None

    # continue asking user for command until it quits
    while True:
        try:
            command = input()
        except EOFError:
            break

        parts = command.split()

        # Connect 
        if len(parts) == 3 and parts[0] == "connect":

            if control_socket is not None:
                print("500 status code received.")
                continue

            server_ip = parts[1]

            try:
                control_port = int(parts[2])
            except ValueError:
                continue

            control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                control_socket.connect((server_ip, control_port))
                control_socket.sendall(command.encode())

                
                response = recv_connect_response(control_socket)
                response_parts = response.split("\n\n", 1)

                if get_status(response) == "200" and len(response_parts) > 1:

                    data_lines = response_parts[1].strip().split("\n", 1)
                    data_port = int(data_lines[0].strip())

                    # save the servers public key for encrypting everything we send
                    server_public_key = serialization.load_pem_public_key(
                        data_lines[1].strip().encode()
                    )

                    print(
                        "200 status code received. "
                        "Starting data connection on port",
                        data_port
                    )

                    # create data socket and connect to the data port
                    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_socket.connect((server_ip, data_port))

                    # start thread to listen for messages on the data socket
                    receiver_thread = threading.Thread(
                        target=receive_messages,
                        args=(data_socket,),
                        daemon=True
                    )
                    receiver_thread.start()
                else:
                    print("500 status code received.")
                    control_socket.close()
                    control_socket = None


            except (ConnectionError, OSError, ValueError, IndexError):
                print("500 status code received.")

                if control_socket is not None:
                    control_socket.close()

                control_socket = None
                data_socket = None

        # Login - username + public key, encrypted with the server's key
        elif len(parts) == 2 and parts[0] == "login":
            if control_socket is None or data_socket is None:
                continue

            response_event.clear()

            pending_login = parts[1]

            
            send_encrypted(
                control_socket,
                "login\n\n" + parts[1] + "\n" + public_pem
            )

            response = wait_for_response()

            if get_status(response) == "200":
                print("200 status code received. Login successful")
            else:
                print("500 status code received.")



        elif command == "who":
            if control_socket is None or data_socket is None:
                continue

            response_event.clear()
            send_encrypted(control_socket, command)

            response = wait_for_response()

            response_parts = response.split("\n\n", 1)

            if get_status(response) == "200":
                users = ""

                if len(response_parts) > 1:
                    users = response_parts[1].strip()

                print(
                    "200 status code received. "
                    "Users currently connected:",
                    users
                )
            else:
                print("500 status code received.")

        # Broadcast
        elif len(parts) >= 2 and parts[0] == "broadcast":
            if control_socket is None or data_socket is None:
                continue

            send_encrypted(control_socket, command)

        # Private message
        elif len(parts) >= 3 and parts[0] == "private":
            if control_socket is None or data_socket is None:
                continue

            response_event.clear()
            send_encrypted(control_socket, command)

            response = wait_for_response()

            if get_status(response) == "200":
                print("200 status code received. Message sent.")
            else:
                print("500 status code received.")

        # Quit
        elif command == "quit":
            if control_socket is None or data_socket is None:
                break

            response_event.clear()

            try:
                send_encrypted(control_socket, command)

                response = wait_for_response()

                if get_status(response) == "200":
                    print("200 status code received.")
                else:
                    print("500 status code received.")

            except (ConnectionError, OSError):
                pass

            control_socket.close()
            data_socket.close()

            break


if __name__ == "__main__":
    main()
