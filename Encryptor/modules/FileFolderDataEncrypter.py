import hashlib
import sys
import os
import shutil

# Prompt for encryption password and derive a 5-byte key from SHA-256
password = input("Enter encryption password: ").strip()
key = hashlib.sha256(password.encode()).digest()[:5]

def encrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        data = bytearray(file.read())
    for i in range(len(data)):
        data[i] = (data[i] + key[i % len(key)]) % 256
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as file:
        file.write(data)
    print(f"Encrypted: {input_path}")

def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as file:
        data = bytearray(file.read())
    for i in range(len(data)):
        data[i] = (data[i] - key[i % len(key)]) % 256
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as file:
        file.write(data)
    print(f"Decrypted: {input_path}")

def process_folder(mode, input_dir, output_dir):
    for root, dirs, files in os.walk(input_dir):
        for dir in dirs:
            rel_path = os.path.relpath(os.path.join(root, dir), input_dir)
            os.makedirs(os.path.join(output_dir, rel_path), exist_ok=True)

        for file in files:
            input_path = os.path.join(root, file)
            relative_path = os.path.relpath(input_path, input_dir)
            output_path = os.path.join(output_dir, relative_path)

            if mode == 'encrypt':
                encrypt_file(input_path, output_path)
            elif mode == 'decrypt':
                decrypt_file(input_path, output_path)

def process(mode, input_path, output_path):
    if os.path.isfile(input_path):
        # Make sure output path is a file, not a directory
        if os.path.isdir(output_path):
            print(f"Error: Output path '{output_path}' must be a file when input is a file.")
            sys.exit(1)

        if mode == 'encrypt':
            encrypt_file(input_path, output_path)
        elif mode == 'decrypt':
            decrypt_file(input_path, output_path)
    elif os.path.isdir(input_path):
        process_folder(mode, input_path, output_path)
    else:
        print(f"Error: '{input_path}' is not a valid file or directory.")
        sys.exit(1)

# Argument validation
if len(sys.argv) != 4:
    print("Usage: python Encrypter.py <encrypt|decrypt> <input_path> <output_path>")
    sys.exit(1)

mode, input_path, output_path = sys.argv[1:]

if mode not in ('encrypt', 'decrypt'):
    print("Invalid mode. Use 'encrypt' or 'decrypt'.")
    sys.exit(1)

# Begin processing
process(mode, input_path, output_path)

# Ask user if they want to delete the original input
confirm = input(f"Delete the original '{input_path}'? (yes/no): ").strip().lower()
if confirm in ('yes', 'y'):
    if os.path.isfile(input_path):
        os.remove(input_path)
    else:
        shutil.rmtree(input_path)
    print(f"Deleted original: {input_path}")
else:
    print("Original not deleted.")
