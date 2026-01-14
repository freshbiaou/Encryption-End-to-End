# client.py
import sys
import asyncio
import threading
import queue
import base64
import ssl
import logging
import websockets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel, QMessageBox
)
from PyQt5.QtCore import QTimer

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

SERVER_URI = "wss://localhost:6789"

class ChatClient:
    def __init__(self, uri):
        self.uri = uri
        self.ws = None
        self.username = None
        self.recv_queue = queue.Queue()
        # RSA app-layer keys
        self.key = RSA.generate(2048)
        self.pub_pem = self.key.publickey().export_key(format='PEM').decode()
        print("CLIENT PEM:\n", self.pub_pem)
        self.priv_cipher = PKCS1_OAEP.new(self.key)
        self.server_pub_cipher = None
        # SSL context
        self.ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_ctx.load_verify_locations("cert.pem")
        # For self-signed certs, uncomment:
        # self.ssl_ctx.check_hostname = False
        # self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def start(self):
        self.loop = asyncio.new_event_loop()
        t = threading.Thread(target=self._run_loop, daemon=True)
        t.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._connect())
            self.loop.run_forever()
        except Exception:
            logging.exception("Client loop error")
            self.recv_queue.put("Connection error: see logs")

    async def _connect(self):
        logging.info(f"Connecting to {self.uri}")
        self.ws = await websockets.connect(self.uri, ssl=self.ssl_ctx)
        # receive server public key
        init = await self.ws.recv()
        if init.startswith("SERVER_PUBLIC_KEY:"):
            pem = init.split(":",1)[1]
            self.server_pub_cipher = PKCS1_OAEP.new(RSA.import_key(pem))
        else:
            raise RuntimeError("Expected server public key")
        # username handshake
        while True:
            msg = await self.ws.recv()
            if msg == "ENTER_USERNAME":
                await self.ws.send(self.username)
            elif msg == "USERNAME_TAKEN":
                self.recv_queue.put("USERNAME_TAKEN")
            elif msg == "USERNAME_OK":
                break
        # ✅ FIXED: Send raw PEM (not base64 encoded)
        await self.ws.send(self.pub_pem)
        self.recv_queue.put(msg)
        asyncio.create_task(self._receiver())

    async def _receiver(self):
        try:
            async for b64 in self.ws:
                try:
                    ct = base64.b64decode(b64)
                    pt = self.priv_cipher.decrypt(ct).decode()
                    self.recv_queue.put(pt)
                except Exception:
                    logging.warning("Failed to decrypt message")
        except Exception:
            logging.exception("Receiver error")
            self.recv_queue.put("Server disconnected")

    async def _send(self, message):
        if not self.server_pub_cipher:
            raise RuntimeError("Server public key not set")
        ct = self.server_pub_cipher.encrypt(message.encode())
        await self.ws.send(base64.b64encode(ct).decode())

    def send_message(self, message):
        asyncio.run_coroutine_threadsafe(self._send(message), self.loop)

class ChatWindow(QWidget):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.poll)
        self.timer.start(100)

    def init_ui(self):
        self.setWindowTitle('Secure Chat (WSS + RSA)')
        self.resize(600, 400)
        self.layout = QVBoxLayout()

        self.login_layout = QHBoxLayout()
        self.login_label = QLabel('Username:')
        self.login_input = QLineEdit()
        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.on_login)
        self.login_layout.addWidget(self.login_label)
        self.login_layout.addWidget(self.login_input)
        self.login_layout.addWidget(self.login_button)
        self.layout.addLayout(self.login_layout)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.layout.addWidget(self.chat_display)

        self.message_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setDisabled(True)
        self.send_button = QPushButton('Send')
        self.send_button.setDisabled(True)
        self.send_button.clicked.connect(self.on_send)
        self.message_layout.addWidget(self.message_input)
        self.message_layout.addWidget(self.send_button)
        self.layout.addLayout(self.message_layout)

        self.setLayout(self.layout)

    def on_login(self):
        username = self.login_input.text().strip()
        if not username:
            QMessageBox.warning(self, 'Input Error', 'Please enter a username.')
            return
        self.client.username = username
        self.client.start()
        self.login_input.setDisabled(True)
        self.login_button.setDisabled(True)
        self.message_input.setDisabled(False)
        self.send_button.setDisabled(False)

    def on_send(self):
        msg = self.message_input.text().strip()
        if msg:
            self.client.send_message(msg)
            self.message_input.clear()

    def poll(self):
        while not self.client.recv_queue.empty():
            msg = self.client.recv_queue.get()
            if msg.startswith('Connection error'):
                QMessageBox.critical(self, 'Connection Error', msg)
                return
            if msg == 'USERNAME_TAKEN':
                QMessageBox.critical(self, 'Error', 'Username taken. Please choose another.')
                self.login_input.setDisabled(False)
                self.login_button.setDisabled(False)
                self.login_input.clear()
                self.message_input.setDisabled(True)
                self.send_button.setDisabled(True)
                self.chat_display.clear()
                return
            if msg.startswith('Server disconnected') or msg.startswith('Send failed'):
                QMessageBox.warning(self, 'Disconnected', msg)
                return
            self.chat_display.append(msg)

def main():
    app = QApplication(sys.argv)
    client = ChatClient(SERVER_URI)
    window = ChatWindow(client)
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
