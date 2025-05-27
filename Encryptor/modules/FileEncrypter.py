import hashlib
import sys

password = input("Enter encryption password: ")

key = hashlib.sha256(password.encode()).digest()[0]

def encrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        data = bytearray(file.read())
    for i in range(len(data)):
        data[i] = (data[i] + key) % 256
    with open(output_path, 'wb') as file:
        file.write(data)

def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        data = bytearray(file.read())
    for i in range(len(data)):
        data[i] = (data[i] - key) % 256
    with open(output_path, 'wb') as file:
        file.write(data)

if len(sys.argv) != 4:
    print("Usage: python Encrypter.py <encrypt|decrypt> <input_file> <output_file>")
    sys.exit(1)

mode, input_path, output_path = sys.argv[1:]


if mode == 'encrypt':
    encrypt_file(input_path, output_path)
elif mode == 'decrypt':
    decrypt_file(input_path, output_path)
else:
    print("Invalid mode. Use 'encrypt' or 'decrypt'.")
