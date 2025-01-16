import os
import base64

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


pass_from_user = input("Please enter your password: ")
password = pass_from_user.encode()
# print(pass_from_user)

# salt= b'\xba\xc4\x10z\xcfl\x02_\xb0q\x01P|]\xa7\xf1'

salt = os.urandom(16)

# Open the file in binary write mode and write the byte string directly
with open("salt.txt", "wb") as file:
    file.write(salt)

# Encode the byte string to Base64
base64_salt = base64.b64encode(salt).decode('utf-8')

# Write the Base64-encoded string to a text file
with open("salt_base64.txt", "w") as file:
    file.write(base64_salt)

print(f"Base64 salt stored in salt_base64.txt: {base64_salt}")

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_000_000,
    backend = default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password))

print(key.decode())




