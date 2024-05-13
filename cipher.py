import csv
import random
import string

def parse_csv_file(file_path, delimiter=','):
    # Temporary dictionary to store username-password pairs
    data = {}

    # Open the file and read its contents
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Parse the CSV-like data
    for line in lines[1:]:  # Skipping the header line
        parts = line.strip().split(delimiter)
        if len(parts) >= 2:
            username, password = parts[0], ','.join(parts[1:])
            data[username] = password

    return data

def generate_key():
    key_length = 50
    characters = string.ascii_letters + string.digits + string.punctuation
    key = ''.join(random.choice(characters) for _ in range(key_length))
    return key

def vigenere_encrypt(plaintext, key):
    encrypted_text = ''
    key_length = len(key)
    for i in range(len(plaintext)):
        char = plaintext[i]
        key_char = key[i % key_length]
        if char.isalpha():
            shift = ord(key_char.lower()) - ord('a')
            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def encrypt_dict_values(data, key):
    encrypted_data = {}
    for username, password in data.items():
        encrypted_password = vigenere_encrypt(password, key)
        encrypted_data[username] = encrypted_password
    return encrypted_data

def write_encrypted_data_to_csv(encrypted_data, file_path, delimiter=';'):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=delimiter)
        writer.writerow(['Username', 'Encrypted Password'])  # Writing header
        for username, encrypted_password in encrypted_data.items():
            writer.writerow([username, encrypted_password])

def main(file_path, delimiter=','):
    data = parse_csv_file(file_path, delimiter)
    key = generate_key()
    encrypted_data = encrypt_dict_values(data, key)
    write_encrypted_data_to_csv(encrypted_data, 'encrypted_file.csv', delimiter)

if __name__ == "__main__":
    file_path = input("Enter the file path: ")
    delimiter = input("Enter the delimiter (default is ','): ") or ','
    main(file_path, delimiter)
















