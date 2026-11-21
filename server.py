# CNT4713 Cryptography Project
# Server implementation

import socket
import sys
import threading
import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


# stores connected users and their data sockets
clients = {}

# protects clients dictionary
clients_lock = threading.Lock()

# Serialize complete frames sent to each client data socket.
socket_send_locks = {}
socket_send_locks_guard = threading.Lock()

# encrypt a message using the recipient's public key
def encrypt_message(message, public_key):

    message_bytes = (
        message if isinstance(message, bytes) 
        else message.encode("utf-8")
    )

    # RSA 2048 with OAEP SHA256 can encrypt 190 bytes at a time
    max_chunk_size = 190
    encrypted_chunks = []

    for i in range(0, len(message_bytes), max_chunk_size):

        chunk = message_bytes[i:i + max_chunk_size]

        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_chunks.append(encrypted_chunk)

    return b"".join(encrypted_chunks)


def decrypt_bytes(encrypted_data, private_key):

    block_size = private_key.key_size // 8

    if not encrypted_data or len(encrypted_data) % block_size != 0:
        raise ValueError("Invalid encrypted message")

    decrypted_chunks = []

    for i in range(0, len(encrypted_data), block_size):

        chunk = encrypted_data[i:i + block_size]

        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        decrypted_chunks.append(decrypted_chunk)

    return b"".join(decrypted_chunks)


def decrypt_message(encrypted_data, private_key):
    return decrypt_bytes(encrypted_data, private_key).decode("utf-8")

# receive the specified number of bytes from a socket
def receive_exact(connection, size):

    data = bytearray()

    while len(data) < size:

        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data.extend(chunk)

    return bytes(data)


# send an encrypted message with its length
def send_encrypted(connection, message, public_key):

    encrypted_data = encrypt_message(message, public_key)

    message_length = struct.pack("!I", len(encrypted_data))

    with socket_send_locks_guard:
        send_lock = socket_send_locks.setdefault(connection, threading.Lock())
    with send_lock:
        connection.sendall(message_length + encrypted_data)

# compute SHA256 hash and send it encrypted
def send_message_hash(connection, message, recipient_public_key):

    message_bytes = (
        message if isinstance(message, bytes)
        else message.encode("utf-8")
    )

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message_bytes)
    message_hash = hasher.finalize()

    send_encrypted(
        connection,
        message_hash,
        recipient_public_key
    )

# receive and decrypt an encrypted message
def receive_encrypted(connection, private_key):

    length_bytes = receive_exact(connection, 4)

    message_length = struct.unpack("!I", length_bytes)[0]

    if message_length == 0 or message_length > 8 * 1024 * 1024 or message_length % 256:
        raise ValueError("Invalid message length")

    encrypted_data = receive_exact(connection, message_length)

    print("Received encrypted message")

    return decrypt_message(encrypted_data, private_key)

def receive_encrypted_bytes(connection, private_key):

    length_bytes = receive_exact(connection, 4)
    message_length = struct.unpack("!I", length_bytes)[0]

    if message_length == 0:
        return b""

    if message_length > 8 * 1024 * 1024:
        raise ValueError("File transfer too large")

    encrypted_data = receive_exact(connection, message_length)

    return decrypt_bytes(encrypted_data, private_key)

# send encrypted messages to all connected users
def send_to_all(message, exclude=None):

    with clients_lock:
        connections = list(clients.values())

    for connection, public_key in connections:

        if connection is exclude:
            continue

        try:
            send_encrypted(connection, message, public_key)

        except (ConnectionError, OSError, ValueError):
            pass


# handles commands from a connected client
def handle_client(control_connection, data_connection, private_key):

    username = None
    client_public_key = None

    try:

        while True:

            # receive encrypted command through control connection
            try:
                command = receive_encrypted(
                control_connection,
                private_key
            ).strip()

            except (ValueError, ConnectionError):
                break

            if not command:
                break

            # divide command into command name and optional argument
            parts = command.split(maxsplit=1)


             # LOGIN
            if len(parts) == 2 and parts[0] == "login":

                if username is not None:
                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )
                    continue

                # get username and public key from decrypted login
                login_lines = [
                    line.strip()
                    for line in parts[1].splitlines()
                    if line.strip()
                ]

                try:
                    if len(login_lines) < 3:
                        raise ValueError("Missing login information")

                    requested_username = login_lines[0]

                    if (
                        not requested_username
                        or any(ch.isspace() for ch in requested_username)
                    ):
                        raise ValueError("Invalid username")

                    public_key_pem = (
                        "\n".join(login_lines[1:]) + "\n"
                    )

                    parsed_key = serialization.load_pem_public_key(
                        public_key_pem.encode("utf-8")
                    )

                    if (
                        not isinstance(parsed_key, rsa.RSAPublicKey)
                        or parsed_key.key_size != 2048
                    ):
                        raise ValueError("Invalid RSA public key")

                except (ValueError, TypeError):
                    # A malformed login may not contain a usable client key.
                    # Without a key, an encrypted failure response is impossible.
                    break

                print(
                    "Login requested by:",
                    requested_username
                )

                # check if username already exists
                with clients_lock:

                    if requested_username in clients:
                        login_successful = False

                    else:
                        clients[requested_username] = (
                            data_connection,
                            parsed_key
                        )

                        username = requested_username
                        client_public_key = parsed_key
                        login_successful = True

                if login_successful:

                    send_encrypted(
                        data_connection,
                        "200\n\n",
                        client_public_key
                    )

                    join_message = (
                        "200\n\n"
                        "join\n"
                        + username
                    )

                    send_to_all(
                        join_message,
                        exclude=data_connection
                    )

                else:
                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        parsed_key
                    )
                 

            # LIST
            elif command == "list":

                # must be logged in
                if username is None:
                    break

                print(
                    f"List requested by {username}. Sending files."
                )

                try:

                    # get all files in current server directory
                    files = [
                        name
                        for name in os.listdir(".")
                        if os.path.isfile(name)
                    ]

                    # keep output consistent
                    files.sort()

                    # assignment requires comma-separated list
                    file_list = ", ".join(files)

                    response = (
                        "200\n\n"
                        + file_list
                    )

                    # list is returned through data connection
                    send_encrypted(
                        data_connection,
                        response,
                        client_public_key
                    )


                except OSError:

                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )

            # STOR
            elif (
                len(parts) == 2
                and parts[0] == "stor"
            ):

                # must be logged in
                if username is None:
                    break

                filename = parts[1]

                print(
                    f"Stor {filename} requested by {username}"
                )

                try:

                    # receive file contents through DATA connection
                    file_data = receive_encrypted_bytes(
                        data_connection,
                        private_key
                    )

                    # create/write file on server
                    with open(filename, "wb") as file:
                        file.write(file_data)

                    print("STOR complete")

                    # only status code is returned
                    send_encrypted(
                        data_connection,
                        "200\n\n",
                        client_public_key
                    )

                except (OSError, ConnectionError, ValueError):

                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )


            # RETR
            elif (
                len(parts) == 2
                and parts[0] == "retr"
            ):

                # must be logged in
                if username is None:
                    break

                filename = parts[1]

                print(
                    f"Retr requested by {username}. "
                    f"Sending file: {filename}"
                )

                # requested file must exist
                if not os.path.isfile(filename):

                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )

                    continue

                try:

                    # open file as binary
                    with open(filename, "rb") as file:
                        file_data = file.read()

                    # status code + blank line + file contents
                    response = (
                        b"200\n\n"
                        + file_data
                    )

                    send_encrypted(
                        data_connection,
                        response,
                        client_public_key
                    )

                    print("File sent.")

                except (OSError, ConnectionError):

                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )


            # DELE
            elif (
                len(parts) == 2
                and parts[0] == "dele"
            ):

                # must be logged in
                if username is None:
                    break

                filename = parts[1]

                print(
                    f"Dele requested by {username}. "
                    f"Deleting file: {filename}"
                )

                try:

                    # file has to exist
                    if not os.path.isfile(filename):

                        send_encrypted(
                            data_connection,
                            "500\n\n",
                            client_public_key   
                        )

                        continue

                    # delete requested file
                    os.remove(filename)

                    print("Delete complete")

                    # only status code returned
                    send_encrypted(
                        data_connection,
                        "200\n\n",
                        client_public_key
                    )

                except OSError:

                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key   
                    )

            # WHO
            elif command == "who":

                if username is None:
                    break

                print("Who requested. Sending users.")

                with clients_lock:
                    usernames = ", ".join(clients.keys())

                response = "200\n\n" + usernames

                send_encrypted(
                    data_connection,
                    response,
                    client_public_key
                )

                       # BROADCAST
            elif len(parts) == 2 and parts[0] == "broadcast":

                if username is None:
                    break

                message = parts[1]

                print("Broadcast requested by", username)
                print("Message:", message)

                response = (
                    "200\n\n"
                    "Broadcast\n"
                    + username + "\n" + message
                )

                send_to_all(response)

            # PRIVATE
            elif len(parts) == 2 and parts[0] == "private":

                if username is None:
                    break

                private_parts = parts[1].split(maxsplit=1)

                if len(private_parts) != 2:
                    send_encrypted(
                        data_connection, "500\n\n",
                        client_public_key
                    )
                    continue

                recipient = private_parts[0]
                message = private_parts[1]

                print(
                    "Private message from",
                    username, "to", recipient
                )

                with clients_lock:
                    recipient_info = clients.get(recipient)

                if recipient_info is not None:

                    recipient_socket, recipient_key = recipient_info

                    private_message = (
                        "200\n\n"
                        "Private\n"
                        + username + "\n" + message
                    )

                    try:
                        send_encrypted(
                            recipient_socket,
                            private_message,
                            recipient_key
                        )

                        send_encrypted(
                            data_connection,
                            "200\n\n",
                            client_public_key
                        )

                    except (ConnectionError, OSError, ValueError):
                        send_encrypted(
                            data_connection,
                            "500\n\n",
                            client_public_key
                        )

                else:
                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )

                        # QUIT
            elif command == "quit":

                print("Quit requested by", username)

                if username is not None:
                    send_encrypted(
                        data_connection,
                        "200\n\n",
                        client_public_key
                    )
                break

            # INVALID COMMAND
            else:

                if client_public_key is not None:
                    send_encrypted(
                        data_connection,
                        "500\n\n",
                        client_public_key
                    )
                else:
                    data_connection.sendall(b"500\n\n")

    # stop one bad/disconnected client from crashing server
    except (ConnectionError, OSError):
        pass


    finally:

        # remove user when connection closes
        if username is not None:

            with clients_lock:

                if username in clients:
                    del clients[username]

            logout_message = (
                "200\n\n"
                "Logout\n"
                + username
            )

            send_to_all(logout_message)


        try:
            control_connection.close()

        except OSError:
            pass


        try:
            data_connection.close()

        except OSError:
            pass

        with socket_send_locks_guard:
            socket_send_locks.pop(data_connection, None)


# START SERVER
def main():

    print("Starting server...")

    # server must receive control port from command line
    if len(sys.argv) != 2:

        print(
            "Usage: python server.py <control_port>"
        )

        sys.exit(1)


    try:

        control_port = int(
            sys.argv[1]
        )

    except ValueError:

        print(
            "Control port must be a number."
        )

        return

        # generate RSA 2048-bit key pair
    print("Creating RSA keypair")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # get the server's public key
    public_key = private_key.public_key()

    # convert public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    print("RSA keypair created")
    print("Creating server socket")


    # create TCP control socket
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )


    # allow port reuse
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )


    # bind server to requested control port
    server_socket.bind(
        ("", control_port)
    )


    server_socket.listen()


    print("Awaiting connections...")


    while True:
        control_connection, client_address = server_socket.accept()
        threading.Thread(
            target=setup_connection,
            args=(control_connection, private_key, public_key_pem),
            daemon=True,
        ).start()


def setup_connection(control_connection, private_key, public_key_pem):
    """Perform the plaintext handshake without blocking new clients."""
    data_listener = None
    try:
        control_connection.settimeout(10)
        command = control_connection.recv(1024).decode('utf-8').strip()
        fields = command.split()
        if len(fields) != 3 or fields[0] != 'connect':
            control_connection.sendall(b'500\n\n')
            return
        # The client-supplied IP/port are handshake fields, not a trusted destination.
        print('Connection requested. Creating data socket')
        data_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_listener.bind(('', 0))
        data_listener.listen(1)
        data_listener.settimeout(10)
        data_port = data_listener.getsockname()[1]
        response = '200\n\n' + str(data_port) + '\n' + public_key_pem
        control_connection.sendall(response.encode('utf-8'))
        data_connection, _ = data_listener.accept()
        control_connection.settimeout(None)
        data_connection.settimeout(None)
        handle_client(control_connection, data_connection, private_key)
    except (OSError, UnicodeError, ValueError):
        pass
    finally:
        if data_listener is not None:
            data_listener.close()
        control_connection.close()



if __name__ == "__main__":
    main()
