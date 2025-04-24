import os
import io
import json
import requests
from collections import namedtuple
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from kms_connection import generate_data_key, decrypt_data_key
from client_config import SERVER_URL

FileInfo = namedtuple('FileInfo', ['path', 'hash'])


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
                file_list.append(FileInfo(rel_path.replace("\\", "/"), file_hash))

            except Exception as e:
                print(f'File path {full_path} error - {e}')
    return file_list


def check_missing_hashes(hashes, backup_name) -> list | None:
    """
    Sends a list of hashes to the server and returns the missing ones.

    :param hashes: List of hash strings to check
    :param backup_name: Name of the backup
    :returns A list of missing hashes
    """
    payload = {'backup': backup_name, 'hashes': hashes}

    response = requests.post(SERVER_URL+'/check_hashes', json=payload)
    if response.status_code == 200:
        result = response.json()
        return result.get('missing_hashes', [])
    else:
        print("Error:", response.text)
        exit()


def encrypt_data(data, output_filename):
   
    print("Encrypting data into '%s'.", output_filename)

    encrypted_key, plaintext_key = generate_data_key()

    # Create a new AES cipher object in CBC mode with a random IV
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(plaintext_key, AES.MODE_CBC, iv)

    # Pad the data to a multiple of AES block size (16 bytes)
    padded_data = pad(data, AES.block_size)

    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)

    del plaintext_key

    print("Encryption completed successfully.")

    return iv + ciphertext, encrypted_key


def send_data_files(pair_list, directory):
    files = []
    files_keys = []
    for file_path, file_hash in pair_list:
        try:
            full_path = os.path.join(directory, file_path)
            with open(full_path, 'rb') as f:
                plaintext = f.read()

            encrypted_data, encrypted_key = encrypt_data(plaintext, file_path)

            files.append(('files', (file_hash, io.BytesIO(encrypted_data))))

            key_filename = file_hash
            files_keys.append(('files', (key_filename, io.BytesIO(encrypted_key))))
        except Exception as e:
            print(f"Error opening file {file_path} (hash {file_hash}): {e}")

    try:
        response_files = requests.post(SERVER_URL+'/upload_data_files', files=files)
        response_keys = requests.post(SERVER_URL+'/upload_key_files', files=files_keys)
        # Close all file objects after the request.
        for _, file_info in files:
            file_info[1].close()

        # Raise an exception if the status code indicates an error.
        for response in (response_files, response_keys):
            response.raise_for_status()
        # return response.json()
    except requests.exceptions.RequestException as err:
        print(f"HTTP Request failed: {err}")
        # return None

def send_meta_file(pairs: list, backup_name: str):
    file_obj = io.StringIO(json.dumps(pairs, indent=4))
    files = {'file': (backup_name, file_obj)}
    response = requests.post(SERVER_URL+'/upload_meta_file', files=files)
    return response.status_code, response.json()


def get_backup_versions(backup_name: str):
    response = requests.post(SERVER_URL+'/list_backup_versions', json={'backup': backup_name})
    if response.status_code != 200:
        raise ValueError('bad response')
    return response.json()


def main():
    dir_to_back = input("Directory to backup: ").strip()
    backup_name = input('Backup name: ').strip()
    if not os.path.isdir(dir_to_back):
        print('Directory does not exist')
        return
    
    print(f'Scanning {dir_to_back}... ')
    path_hash_pairs = scan(dir_to_back)
    # print('Path-hash pairs:', path_hash_pairs)
    hash_list = [pair.hash for pair in path_hash_pairs]
    missing_hashes = check_missing_hashes(hash_list, backup_name)
    print('Missing hashes:', missing_hashes)
    if missing_hashes:
        to_upload = [pair for pair in path_hash_pairs if pair.hash in missing_hashes]
        print(send_data_files(to_upload, dir_to_back))
    else:
        print('All data files are in the server, nothing to do')

    print('Sending backup meta file')
    code, message = send_meta_file(path_hash_pairs, backup_name)
    if code == 200:
        print('Backup created')
    else:
        print('Error creating backup:', message)


if __name__ == "__main__":
    main()
