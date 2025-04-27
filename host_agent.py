import os
import io
import json
import shutil
import tempfile
import requests
from collections import namedtuple
from itertools import starmap
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from kms_connection import generate_data_key, decrypt_data_key
from client_config import SERVER_URL

FileInfo = namedtuple('FileInfo', ['path', 'hash'])

BAD_FILE_CHARS = '/\\\0:'


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

    response = requests.post(SERVER_URL + '/check_hashes', json=payload)
    if response.status_code == 200:
        result = response.json()
        return result.get('missing_hashes', [])
    else:
        print("Error:", response.text)
        exit()


def encrypt_data(data):
    encrypted_key, plaintext_key = generate_data_key()

    # Create a new AES cipher object in CBC mode with a random IV
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(plaintext_key, AES.MODE_CBC, iv)

    # Pad the data to a multiple of AES block size (16 bytes)
    padded_data = pad(data, AES.block_size)

    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)

    del plaintext_key

    return iv + ciphertext, encrypted_key


def decrypt_data(encrypted_blob: bytes,
                 encrypted_key: bytes,
                 output_filename: str) -> bytes:
    print(f"Decrypting data...")

    plaintext_key = decrypt_data_key(encrypted_key)

    try:
        # Split out IV and ciphertext
        iv = encrypted_blob[:AES.block_size]
        ciphertext = encrypted_blob[AES.block_size:]

        cipher = AES.new(plaintext_key, AES.MODE_CBC, iv)
        padded_plain = cipher.decrypt(ciphertext)

        plaintext = unpad(padded_plain, AES.block_size)

        with open(output_filename, "wb") as f:
            f.write(plaintext)
        print(f"Decrypted data written to '{output_filename}'.")

        return plaintext

    finally:
        del plaintext_key


def send_data_files(pair_list, directory):
    files = []
    files_keys = []
    for file_path, file_hash in pair_list:
        try:
            full_path = os.path.join(directory, file_path)
            with open(full_path, 'rb') as f:
                plaintext = f.read()

            print(f"Encrypting file {file_path}.")
            encrypted_data, encrypted_key = encrypt_data(plaintext)
            print("Encryption completed successfully.")

            files.append(('files', (file_hash, io.BytesIO(encrypted_data))))

            key_filename = file_hash
            files_keys.append(('files', (key_filename, io.BytesIO(encrypted_key))))
        except Exception as e:
            print(f"Error opening file {file_path} (hash {file_hash}): {e}")

    try:
        response_files = requests.post(SERVER_URL + '/upload_data_files', files=files)
        response_keys = requests.post(SERVER_URL + '/upload_key_files', files=files_keys)
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
    response = requests.post(SERVER_URL + '/upload_meta_file', files=files)
    return response.status_code, response.json()


def get_backup_metadata(backup_name: str, version: str) -> dict:
    response = requests.get(SERVER_URL + '/get_meta_file', params={'backup': backup_name, 'version': version})
    response.raise_for_status()
    # should decrypt there if there is encryption
    response_content = response.content.decode()
    return json.loads(response_content)


def get_backup_versions(backup_name: str):
    response = requests.post(SERVER_URL + '/list_backup_versions', json={'backup': backup_name})
    if response.status_code != 200:
        raise ValueError('bad response')
    return response.json()


def get_and_restore(directory: str, backup_name: str, version: str) -> bool:
    with tempfile.TemporaryDirectory() as tmpdir:
        restoring_error = False
        backup_meta = get_backup_metadata(backup_name, version)
        for raw_file_info in backup_meta:
            print('RAW FILE INFO:', raw_file_info)
            file_info = FileInfo(*raw_file_info)
            file_path = os.path.join(tmpdir, file_info.path)
            resp_file = requests.get(SERVER_URL + '/get_data_file/' + file_info.hash)
            if resp_file.status_code != 200:
                print('An error occurred while downloading file')
                restoring_error = True
                continue
            resp_key = requests.get(SERVER_URL + '/get_key_file/' + file_info.hash)
            resp_key.raise_for_status()
            if resp_key.status_code != 200:
                print('An error occurred while downloading key')
                restoring_error = True
                continue
            decrypt_data(resp_file.content, resp_key.content, file_path)
        if restoring_error:
            target_path = f"{directory}.incomplete"
            # to make sure that directory didn't exist
            while os.path.exists(target_path):
                target_path = f"{target_path}.incomplete"
            print(f'An error occurred while restoring backup, restored data will be written to {target_path}')
        else:
            target_path = directory
            shutil.rmtree(directory, ignore_errors=True)
        shutil.copytree(tmpdir, target_path)
        return not restoring_error


def is_valid_filename(name: str) -> bool:
    if len(name) < 1:
        return False
    for char in BAD_FILE_CHARS:
        if char in name:
            return False
    return True


def main():
    option = input("What do you want to do? (backup or restore): ").lower()
    if 'backup'.startswith(option):
        while not os.path.isdir(
                dir_to_back := input("Directory to backup: ").strip()
        ):
            print('Directory does not exist, provide a valid one')

        while not is_valid_filename(
                backup_name := input('Backup name: ').strip()
        ):
            print(f'Invalid backup name: should be at least 1 character long '
                  f'and contain no characters as "{BAD_FILE_CHARS}"')

        print(f'Scanning {dir_to_back}... ')
        path_hash_pairs = scan(dir_to_back)
        hash_list = [pair.hash for pair in path_hash_pairs]
        missing_hashes = check_missing_hashes(hash_list, backup_name)
        print('Missing hashes:', missing_hashes)
        if missing_hashes:
            to_upload = [pair for pair in path_hash_pairs if pair.hash in missing_hashes]
            send_data_files(to_upload, dir_to_back)
            print('Missing files sent to server')
        else:
            print('All data files are in the server, nothing to do')

        print('Sending backup meta file')
        code, message = send_meta_file(path_hash_pairs, backup_name)
        if code == 200:
            print('Backup created')
        else:
            print('Error creating backup:', message)
    elif 'restore'.startswith(option):
        dir_to_restore = input('Directory to restore: ').strip()
        backup_name = input('Backup name: ').strip()
        print('Select version that you want to restore:')
        available_versions: list = get_backup_versions(backup_name)
        for i, version_info in enumerate(available_versions):
            version = version_info.get('version_id')
            last_modified = version_info.get('last_modified')
            print(str(i)+')', version, last_modified, sep='\t')
        version_no = int(input('Select number: '))

        if get_and_restore(dir_to_restore, backup_name, available_versions[version_no]['version_id']):
            print('Backup restored properly')
    else:
        print('Invalid option')

if __name__ == "__main__":
    main()
