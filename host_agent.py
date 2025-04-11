import os
import json
from Crypto.Hash import SHA256

def hash_file(filepath):
    hash_tool = SHA256.new()

    with open(filepath, 'rb') as f:
        
        while True:
            chunker = f.read(8_192_000)  # file read in 8MB chunks
            if not chunker:
                break
            hash_tool.update(chunker)
    return hash_tool.hexdigest()

def scan(directory):
    file_list = []

    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, directory)

            try:
                file_hash = hash_file(full_path)
                file_list.append({'path': rel_path.replace("\\", "/"), 'hash': file_hash})

            except Exception as e:
                print(f'File path {full_path} error - {e}')
    return file_list

def main():
    dir_to_back = input("Directory to backup: ").strip()
    if not os.path.isdir(dir_to_back):
        print('Directory does not exist')
        return
    
    print(f'Scanning {dir_to_back}... ')
    list_of_files = scan(dir_to_back)

    output = 'file_hashes.json'
    with open(output, 'w') as o:
        json.dump(list_of_files, o, indent=2)

    print(f'Found {len(list_of_files)} files. Saved in {output}')

if __name__ == "__main__":
    main()