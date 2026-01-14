# server.py
import asyncio
import websockets
import base64
import ssl
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Configure logging to console
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s: %(message)s')

# SSL/TLS context for WSS
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

# Mapping username -> {'ws': websocket, 'pubkey': RSA key}
clients = {}

# Generate server RSA key pair for application-level encryption
server_key = RSA.generate(2048)
server_pub_pem = server_key.publickey().export_key().decode()
server_cipher = PKCS1_OAEP.new(server_key)

async def register(websocket):
    # Send server public key
    await websocket.send("SERVER_PUBLIC_KEY:" + server_pub_pem)
    # Prompt for username
    await websocket.send("ENTER_USERNAME")
    while True:
        username = await websocket.recv()
        if username and username not in clients:
            await websocket.send("USERNAME_OK")
            break
        else:
            await websocket.send("USERNAME_TAKEN")

    # Receive client public key
    client_pub_pem = await websocket.recv()
    logging.debug("Raw client_pub_pem received (first 200 chars): %s", client_pub_pem[:200])
    try:
        client_pubkey = RSA.import_key(client_pub_pem)
    except ValueError:
        logging.error("Invalid client public key format:\n%s", client_pub_pem)
        raise
    clients[username] = {'ws': websocket, 'pubkey': client_pubkey}
    await broadcast(f"{username} joined the chat.")
    return username

async def unregister(username):
    clients.pop(username, None)
    await broadcast(f"{username} left the chat.")

async def broadcast(message, sender=None):
    formatted = f"{sender}: {message}" if sender else message
    for user, info in clients.items():
        ws = info['ws']
        pubkey = info['pubkey']
        try:
            cipher = PKCS1_OAEP.new(pubkey)
            ciphertext = cipher.encrypt(formatted.encode())
            await ws.send(base64.b64encode(ciphertext).decode())
        except Exception:
            logging.exception(f"Failed to send to {user}")

async def handle_messages(websocket, username):
    async for b64msg in websocket:
        try:
            ciphertext = base64.b64decode(b64msg)
            plaintext = server_cipher.decrypt(ciphertext).decode()
        except Exception:
            logging.warning("Failed to decrypt incoming message")
            continue
        if plaintext.startswith("@"):
            # Private messaging logic
            try:
                target, msg = plaintext.split(" ", 1)
                target = target[1:]
                if target in clients:
                    tgt = clients[target]
                    c = PKCS1_OAEP.new(tgt['pubkey'])
                    tgt_ct = base64.b64encode(c.encrypt(f"[Private] {username}: {msg}".encode())).decode()
                    await tgt['ws'].send(tgt_ct)
                    snd = clients[username]
                    c2 = PKCS1_OAEP.new(snd['pubkey'])
                    ack = base64.b64encode(c2.encrypt(f"[To {target}] {msg}".encode())).decode()
                    await snd['ws'].send(ack)
                else:
                    raise KeyError(f"User '{target}' not found.")
            except Exception as e:
                logging.exception("Private message error")
                snd = clients.get(username)
                if snd:
                    try:
                        c2 = PKCS1_OAEP.new(snd['pubkey'])
                        err = base64.b64encode(c2.encrypt(str(e).encode())).decode()
                        await snd['ws'].send(err)
                    except Exception:
                        logging.exception("Failed to send error to sender")
        else:
            await broadcast(plaintext, sender=username)

async def handler(websocket, path=None):
    username = None
    try:
        username = await register(websocket)
        await handle_messages(websocket, username)
    except Exception:
        logging.exception("Handler error")
        await websocket.close(code=1011, reason="Internal server error")
    finally:
        if username:
            try:
                await unregister(username)
            except Exception:
                logging.exception("Unregister error")

async def main():
    logging.info("Starting secure server on wss://localhost:6789")
    async with websockets.serve(handler, "0.0.0.0", 6789, ssl=ssl_ctx):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutdown requested")