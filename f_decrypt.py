import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

pass_from_user = input("Please enter your password: ")
password = pass_from_user.encode()
# print(pass_from_user)

# salt= b'\xba\xc4\x10z\xcfl\x02_\xb0q\x01P|]\xa7\xf1'
# Read the byte string from the file in binary mode
with open("salt.txt", "rb") as file:
    read_salt = file.read()

# # Read the Base64 string from the file
# with open("salt_base64.txt", "r") as file:
#     base64_salt = file.read()

# # Decode the Base64 string back to the original byte string
# decoded_salt = base64.b64decode(base64_salt)

# print(f"Decoded salt: {decoded_salt}")

# read_salt = decoded_salt

salt = read_salt


kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_000_000,
    backend = default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password))

print(key.decode())



# key = input("Please input ur key: ")

cipher = Fernet(key)

filename = input("Please input the encryped file name (enter to use,default,encrypted_secret_excel.xlsx): ")

if not filename or filename.strip() == "":
    filename = 'encrypted_secret_excel.xlsx'

de_file = None
with open(filename, 'rb') as df:
    encrypted_data = df.read()

print(len(encrypted_data)) 

decrypted_data = cipher.decrypt(encrypted_data)

with open("decrypted.xlsx" , 'wb') as ef:
    ef.write(decrypted_data)





