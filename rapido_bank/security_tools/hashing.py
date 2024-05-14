import os

def simple_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        hash_value = 0
        for byte in file_bytes:
            # rotate left and combine with current byte value
            hash_value = ((hash_value << 5) - hash_value + byte) & 0xFFFFFFFFFFFFFFFF

        # Convert hash value to a string base-16 (hexadecimal)
        hash_str = hex(hash_value)[2:].upper()
        hash_str = (hash_str * 10)[:50]
        return hash_str
    
    except Exception as e:
        return f"Error: {str(e)}"

# test
file_path = "recov.csv"
hash_output = simple_hash(file_path)
print("Hash of the file:", hash_output)
