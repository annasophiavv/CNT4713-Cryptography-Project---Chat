# CNT4713 Cryptography Project - Chat
# Client implementation
import os
import socket
import struct
import threading
from collections import deque

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ------------------------------------------------------------

KEY_SIZE = 2048
BLOCK_SIZE = KEY_SIZE // 8
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
CHUNK_SIZE = BLOCK_SIZE - 2 * hashes.SHA256().digest_size - 2
MAX_FRAME = 8 * 1024 * 1024  

def encrypt_bytes(data, public_key):
    if not data:
        raise ValueError('Cannot encrypt an empty payload')
    return b''.join(public_key.encrypt(data[i:i + CHUNK_SIZE], OAEP)
                    for i in range(0, len(data), CHUNK_SIZE))


def decrypt_bytes(data, private_key):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError('Invalid RSA ciphertext length')
    return b''.join(private_key.decrypt(data[i:i + BLOCK_SIZE], OAEP)
                    for i in range(0, len(data), BLOCK_SIZE))


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError('Connection closed')
        result.extend(chunk)
    return bytes(result)

def send_encrypted(sock, data, public_key):
    if isinstance(data, str):
        data = data.encode('utf-8')
    ciphertext = encrypt_bytes(data, public_key)
    if len(ciphertext) > MAX_FRAME:
        raise ValueError('Message exceeds maximum frame size')
    sock.sendall(struct.pack('!I', len(ciphertext)) + ciphertext)


def receive_encrypted(sock, private_key):
    length = struct.unpack('!I', recv_exact(sock, 4))[0]
    if length == 0 or length > MAX_FRAME or length % BLOCK_SIZE:
        raise ValueError('Invalid encrypted frame length')
    return decrypt_bytes(recv_exact(sock, length), private_key)


def receive_connect_response(sock):
    # The current team server sends a plaintext status, data port, and PEM key.
    result = bytearray()
    marker = b'-----END PUBLIC KEY-----'
    while marker not in result:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('Server closed during handshake')
        result.extend(chunk)
        if result.startswith(b'500'):
            break
        if len(result) > 16384:
            raise ValueError('Handshake too large')
    return result.decode('utf-8')

class ChatClient:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
        self.public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.server_key = None
        self.control = None
        self.data = None
        self.username = None
        self.responses = deque()
        self.response_condition = threading.Condition()
        self.send_lock = threading.Lock()
        self.running = False
        self.pending_file = None
        self.pending_file_lock = threading.Lock()

    def connected(self):
        return self.control is not None and self.data is not None

    def close(self):
        self.running = False
        for sock in (self.control, self.data):
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        self.control = self.data = None
        with self.response_condition:
            self.response_condition.notify_all()

    def connect(self, host, port):
        if self.connected() or self.control is not None:
            print('500 status code received.')
            return
        control = None
        data = None
        try:
            control = socket.create_connection((host, int(port)), timeout=10)
            control.settimeout(None)
            control.sendall(f'connect {host} {port}'.encode('utf-8'))
            response = receive_connect_response(control)
            status, separator, payload = response.partition('\n\n')
            if status.strip() != '200' or not separator:
                raise ValueError('Server rejected connection')
            data_port_text, separator, pem = payload.partition('\n')
            if not separator:
                raise ValueError('Server did not supply its public key')
            data_port = int(data_port_text.strip())
            server_key = serialization.load_pem_public_key(pem.strip().encode('utf-8'))
            if not isinstance(server_key, rsa.RSAPublicKey) or server_key.key_size != KEY_SIZE:
                raise ValueError('Unsupported server public key')
            data = socket.create_connection((host, data_port), timeout=10)
            data.settimeout(None)
            self.control, self.data, self.server_key = control, data, server_key
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
            print('200 status code received. Starting data connection on port', data_port)
        except (OSError, ValueError, TypeError):
            print('500 status code received.')
            if control:
                control.close()
            if data:
                data.close()
            self.control = self.data = None

    def send_command(self, text):
        if not self.connected():
            print('500 status code received.')
            return False
        try:
            with self.send_lock:
                send_encrypted(self.control, text, self.server_key)
            return True
        except (OSError, ValueError):
            print('500 status code received.')
            return False

    def await_response(self, timeout=10):
        with self.response_condition:
            if not self.response_condition.wait_for(lambda: self.responses or not self.running,
                                                    timeout=timeout):
                return None
            return self.responses.popleft() if self.responses else None

    def enqueue_response(self, message):
        with self.response_condition:
            self.responses.append(message)
            self.response_condition.notify_all()

    def receive_loop(self):
        try:
            while self.running:
                payload = receive_encrypted(self.data, self.private_key)
                print('Received encrypted message')
                # File retrieval can contain arbitrary bytes, not UTF-8 text.
                with self.pending_file_lock:
                    expecting_file = self.pending_file is not None
                if expecting_file and payload.startswith((b'200\n\n', b'500\n\n')):
                    self.enqueue_response(payload)
                    continue
                try:
                    message = payload.decode('utf-8')
                except UnicodeDecodeError:
                    # An unexpected binary message must not kill the receiver.
                    self.enqueue_response(payload)
                    continue
                if message.startswith('200\n\nBroadcast\n'):
                    parts = message.split('\n', 4)
                    if len(parts) == 5:
                        print('200 status code received.')
                        print(f'Broadcast message from {parts[3]}: {parts[4]}')
                elif message.startswith('200\n\nPrivate\n'):
                    parts = message.split('\n', 4)
                    if len(parts) == 5:
                        print('200 status code received.')
                        print(f'{parts[3]}: {parts[4]}')
                elif message.startswith(('200\n\njoin\n', '200\n\nLogout\n')):
                    # Asynchronous presence notifications are not command replies.
                    pass
                elif len(message) >= 3 and message[:3] in ('200', '500'):
                    self.enqueue_response(payload)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self.running = False
            with self.response_condition:
                self.response_condition.notify_all()

    @staticmethod
    def status(response):
        if response is None:
            return '500'
        return response.split(b'\n', 1)[0].decode('ascii', errors='replace').strip()

    def request(self, command):
        if not self.send_command(command):
            return None
        return self.await_response()

    def login(self, username):
        if self.username is not None:
            print('500 status code received.')
            return
        response = self.request('login\n\n' + username + '\n' + self.public_pem)
        if self.status(response) == '200':
            self.username = username
            print('200 status code received. Login successful')
        else:
            print('500 status code received.')

    def who(self):
        response = self.request('who')
        if self.status(response) == '200':
            users = response.partition(b'\n\n')[2].decode('utf-8', errors='replace')
            print('200 status code received. Users currently connected:', users)
        else:
            print('500 status code received.')

    def broadcast(self, text):
        # Existing team server sends the sender's broadcast back as its success display.
        self.send_command('broadcast ' + text)

    def private(self, username, text):
        response = self.request('private ' + username + ' ' + text)
        if self.status(response) == '200':
            print('200 status code received. Message sent.')
        else:
            print('500 status code received.')
    def list_files(self):
        response = self.request('list')
        if self.status(response) == '200':
            names = response.partition(b'\n\n')[2].decode('utf-8', errors='replace')
            print('200 status code received. Files:', names)
        else:
            print('500 status code received.')

    def store_file(self, filename):
        try:
            with open(filename, 'rb') as f:
                contents = f.read()
            if not contents:
                # Existing server's file-receive helper accepts an empty framed payload.
                encrypted_payload = struct.pack('!I', 0)
            else:
                encrypted = encrypt_bytes(contents, self.server_key)
                if len(encrypted) > MAX_FRAME:
                    raise ValueError('File too large')
                encrypted_payload = struct.pack('!I', len(encrypted)) + encrypted
            if not self.send_command('stor ' + filename):
                return
            # Data socket is full-duplex: receiver only reads; main thread writes.
            with self.send_lock:
                self.data.sendall(encrypted_payload)
            response = self.await_response()
            print('200 status code received. File Sent.' if self.status(response) == '200'
                  else '500 status code received.')
        except (OSError, ValueError, TypeError):
            print('500 status code received.')

    def retrieve_file(self, filename):
        # Flag tells the receiver to preserve binary payload rather than decode it.
        with self.pending_file_lock:
            self.pending_file = filename
        try:
            response = self.request('retr ' + filename)
            if self.status(response) != '200':
                print('500 status code received.')
                return
            contents = response.partition(b'\n\n')[2]
            with open(filename, 'wb') as f:
                f.write(contents)
            print('File retrieved.')
        except OSError:
            print('500 status code received.')
        finally:
            with self.pending_file_lock:
                self.pending_file = None

    def delete_file(self, filename):
        response = self.request('dele ' + filename)
        print('200 status code received. File deleted.' if self.status(response) == '200'
              else '500 status code received.')

    def quit(self):
        if self.connected():
            response = self.request('quit')
            print('200 status code received.' if self.status(response) == '200'
                  else '500 status code received.')
        self.close()

def main():
    print('Starting client...')
    client = ChatClient()
    try:
        while True:
            try:
                command = input()
            except EOFError:
                break
            parts = command.strip().split(maxsplit=2)
            if not parts:
                continue
            action = parts[0]
            if action == 'connect' and len(parts) == 3:
                client.connect(parts[1], parts[2])
            elif action == 'login' and len(parts) == 2:
                client.login(parts[1])
            elif action == 'who' and len(parts) == 1:
                client.who()
            elif action == 'broadcast' and len(parts) >= 2:
                client.broadcast(command.strip().split(maxsplit=1)[1])
            elif action == 'private' and len(parts) == 3:
                client.private(parts[1], parts[2])
            elif action == 'list' and len(parts) == 1:
                client.list_files()
            elif action == 'stor' and len(parts) == 2:
                client.store_file(parts[1])
            elif action == 'retr' and len(parts) == 2:
                client.retrieve_file(parts[1])
            elif action == 'dele' and len(parts) == 2:
                client.delete_file(parts[1])
            elif action == 'quit' and len(parts) == 1:
                client.quit()
                return
            else:
                print('500 status code received.')
    finally:
        client.close()


if __name__ == '__main__':
    main()

