import os

def simple_hash(file_path):
    """Simple hash function to hash the contents of a file into a 50 character string."""
    try:
        # Read file binary data
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        # Base hash value
        hash_value = 0

        # Simple hashing: Combine bytes with arithmetic and bitwise operations
        for byte in file_bytes:
            # Rotate left and combine with current byte value
            hash_value = ((hash_value << 5) - hash_value + byte) & 0xFFFFFFFFFFFFFFFF

        # Convert hash value to a string base-16 (hexadecimal)
        hash_str = hex(hash_value)[2:].upper()

        # Ensure the hash string is exactly 50 characters long
        hash_str = (hash_str * 10)[:50]

        return hash_str
    except Exception as e:
        return f"Error: {str(e)}"

# Example usage:
file_path = "test.txt"  # Replace with your file path
hash_output = simple_hash(file_path)
print("Hash of the file:", hash_output)
