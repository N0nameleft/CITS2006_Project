import os

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        hash_value = 0
        for byte in file_bytes:
            #rotate left and combine with current byte value
            hash_value = ((hash_value << 5) - hash_value + byte) & 0xFFFFFFFFFFFFFFFF

        #Convert hash value to a string base-16 (hexadecimal)
        hash_str = hex(hash_value)[2:].upper()
        hash_str = (hash_str * 10)[:50] #50 chars
        return hash_str
    
    except Exception as e:
        return f"Error: {str(e)}"

def hash_folder(folder_path):
    try:
        hash_value = 0
        
        for root, dirs, files in os.walk(folder_path):
            # Sort directories and files to ensure consistent hashing order
            dirs.sort()
            files.sort()
            
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                dir_hash = hash_folder(dir_path)
                # Combine the directory name and its hash
                combined = dir_name + dir_hash
                for char in combined:
                    hash_value = ((hash_value << 5) - hash_value + ord(char)) & 0xFFFFFFFFFFFFFFFF
            
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_hash = hash_file(file_path)
                # Combine the file name and its hash
                combined = file_name + file_hash
                for char in combined:
                    hash_value = ((hash_value << 5) - hash_value + ord(char)) & 0xFFFFFFFFFFFFFFFF
        
        hash_str = hex(hash_value)[2:].upper()
        hash_str = (hash_str * 10)[:50]  # 50 char long
        return hash_str
    
    except Exception as e:
        return f"Error: {str(e)}"


# test
# file_path = "main.py"
# hash_output = hash_file(file_path)
# print("Hash of the file:", hash_output)
# folder_path = '../'
# print(hash_folder(folder_path))
