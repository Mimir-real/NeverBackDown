import boto3

kms_client = boto3.client('kms')

def generate_data_key():
    response = kms_client.generate_data_key(
        KeyID='', #ARN master key
        KeySpac='AES_256'
    )

    encrypted_data_key = response['CiphertextBlob']
    plaintext_data_key = response['Plaintext']

    return encrypted_data_key, plaintext_data_key

def decrypt_data_key(encrypted_data_key):
    response = kms_client.decrypt(CiphertextBlob = encrypted_data_key)
    decrypted_data_key = response['Plaintext']

    return decrypted_data_key