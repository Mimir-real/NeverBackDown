import boto3
from client_config import MASTER_KEY_ARN

kms_client = boto3.client('kms')

def generate_data_key():
    response = kms_client.generate_data_key(
        KeyId=MASTER_KEY_ARN, #ARN master key
        KeySpec='AES_256'
    )

    encrypted_data_key = response['CiphertextBlob']
    plaintext_data_key = response['Plaintext']

    return encrypted_data_key, plaintext_data_key

def decrypt_data_key(encrypted_data_key):
    response = kms_client.decrypt(
        KeyId=MASTER_KEY_ARN,
        CiphertextBlob=encrypted_data_key
    )
    plaintext_data_key = response['Plaintext']

    return plaintext_data_key

