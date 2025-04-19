import os
import base64
import hashlib
import argparse
from cryptography.fernet import Fernet
from getpass import getpass

ENCRYPT = "encrypt"
DECRYPT = "decrypt"
parser = argparse.ArgumentParser(description="Criptează sau decriptează un text simplu.")
parser.add_argument("action", choices=[ENCRYPT, DECRYPT], help="Alege 'encrypt' sau 'decrypt'")
args = parser.parse_args()

original = os.path.join(os.path.dirname(__file__), "original")
encrypted = os.path.join(os.path.dirname(__file__), "encrypted")
decrypted = os.path.join(os.path.dirname(__file__), "decrypted")

def parola_to_cheie(parola: str) -> bytes:
    # Derivăm o cheie fixă din parolă, fără salt (nu e cel mai sigur, dar e simplu)
    sha = hashlib.sha256(parola.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(sha)  # Format compatibil cu Fernet

def cripteaza(text: str, parola: str) -> bytes:
    key = parola_to_cheie(parola)
    f = Fernet(key)
    return f.encrypt(text.encode())

def decripteaza(token: bytes, parola: str) -> str:
    key = parola_to_cheie(parola)
    f = Fernet(key)
    return f.decrypt(token).decode()


with open(original, "r") as file:
    content = file.read()

parola = getpass("Parola: ")

if args.action == ENCRYPT:
    criptat = cripteaza(content, parola)
    with open(encrypted, "w") as file:
        encoded = base64.b64encode(criptat).decode()
        file.write(encoded)
else:
    with open(encrypted, "r") as file:
        content = file.read()
    decoded = base64.b64decode(content)
    decriptat = decripteaza(decoded, parola)
    with open(decrypted, "w") as file:
        file.write(decriptat)
