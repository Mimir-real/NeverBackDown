import boto3
import base64

kms_client = boto3.client('kms')

def generate_data_key():
    response = kms_client.generate_data_key(
        KeyId='arn:aws:kms:us-east-1:367054200871:key/97db1d85-17f2-41da-ae70-1a1208666c30', #ARN master key
        KeySpec='AES_256'
    )

    encrypted_data_key = response['CiphertextBlob']
    plaintext_data_key = response['Plaintext']

    return encrypted_data_key, plaintext_data_key

def decrypt_data_key(encrypted_data_key):
    response = kms_client.decrypt(CiphertextBlob = encrypted_data_key)
    plaintext_data_key = response['Plaintext']

    return plaintext_data_key