import os
def custom_hash_from_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()

        base_hash = ['A'] * 50 
        prime_numbers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

        for i, byte in enumerate(file_content):
            for j in range(50):
                byte_value = (byte * (prime_numbers[i % 15]) + ord(base_hash[j])) % 123
                if 48 <= byte_value <= 57 or 65 <= byte_value <= 90 or 97 <= byte_value <= 122:
                    base_hash[j] = chr(byte_value)
                else:
                    base_hash[j] = chr(65 + byte_value % 26) 

        final_hash = ''.join(base_hash)
        return final_hash
    except IOError:
        return "Error: File could not be opened. Check the file path."

file_path = "test.txt"
hashed_value = custom_hash_from_file(file_path)
print(f"Hashed output: {hashed_value}")
