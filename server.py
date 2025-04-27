import re
from http.client import responses
from io import BytesIO
from os.path import basename
from flask import Flask, request, jsonify, send_file
import boto3
from botocore.exceptions import ClientError
from server_config import BUCKET_NAME

app = Flask(__name__)

HASHES_PREFIX = 'hash_files/'
KEY_PREFIX = 'key/'

s3_client = boto3.client('s3')

def get_s3_hashes():
    """
    Retrieves a list of file names (hashes) from S3 bucket.
    """
    hashes = set()

    paginator = s3_client.get_paginator('list_objects_v2')
    # Paginate through all objects in the bucket
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=HASHES_PREFIX):
        objects = page.get('Contents', [])
        for obj in objects:

            hashes.add(basename(obj['Key']))
    return hashes


def is_valid_hash(name: str) -> bool:
    return bool(re.fullmatch('^[0-9a-f]{64}$', name))


@app.route('/check_hashes', methods=['POST'])
def check_hashes():
    # Ensure JSON data is provided
    if not request.is_json:
        return jsonify({"error": "Request data must be in JSON format"}), 400

    data = request.get_json()
    client_hashes_list = data.get('hashes')
    if client_hashes_list is None or not isinstance(client_hashes_list, list):
        return jsonify({"error": "JSON payload must include a list of hashes under the 'hashes' key"}), 400

    client_hashes = set(client_hashes_list)
    try:
        s3_hashes = get_s3_hashes()
    except ClientError as e:
        print("Error retrieving S3 objects:", e)
        return jsonify({"error": "Couldn't receive S3 objects"}), 500

    # Compute the difference; only include those hashes from the client that are not in S3
    missing_hashes = client_hashes - s3_hashes

    # Return the result as JSON
    return jsonify({"missing_hashes": list(missing_hashes)}), 200

@app.route('/upload_meta_file', methods=['POST'])
def upload_meta_file():
    if 'file' not in request.files:
        return jsonify(error="No file part in the request"), 400
    if 'key' not in request.files:
        return jsonify(error="No key file part in the request"), 400

    file = request.files['file']
    key = request.files['key']

    # Check if files was actually selected
    if file.filename == "":
        return jsonify(error="No file selected"), 400
    if key.filename == "":
        return jsonify(error="No key file selected"), 400

    # Sanitize the filename
    backup_name = basename(file.filename)
    filename = backup_name + '.json'


    try:
        # Upload file directly to S3
        response = s3_client.put_object(
            Body=file,
            Bucket=BUCKET_NAME,
            Key=filename
        )

        metadata_file_version = response.get('VersionId')
        key_filename = backup_name + '_' + metadata_file_version + '.key'

        s3_client.upload_fileobj(
            Fileobj=key,
            Bucket=BUCKET_NAME,
            Key=key_filename
        )
        return jsonify(message=f"Backup '{backup_name}' meta file and key uploaded successfully to S3."), 200

    except Exception as e:
        # Return an error response if S3 upload fails
        return jsonify(error=f"Error uploading backup '{backup_name}' metadata: {str(e)}"), 500

@app.route('/upload_data_files', methods=['POST'])
def upload_data_files():
    # Validate the request has files under the key 'files'
    if 'files' not in request.files:
        return jsonify(error="No file part in the request"), 400

    files = request.files.getlist('files')

    # Check if files list is empty or first file has an empty filename
    if not files or files[0].filename == "":
        return jsonify(error="No selected files"), 400

    uploaded_files = []
    errors = []

    for file in files:
        filename = file.filename.lower()
        if file and is_valid_hash(filename):
            try:
                # Upload file to S3 using file-like object
                s3_client.upload_fileobj(
                    Fileobj=file,
                    Bucket=BUCKET_NAME,
                    Key=HASHES_PREFIX+filename
                )
                uploaded_files.append(filename)
            except Exception as e:
                errors.append({"filename": filename, "error": str(e)})
        else:
            errors.append({"filename": file.filename, "error": "Name is not a valid hash"})

    response = {"uploaded_files": uploaded_files}
    # If there are errors, include them in the response
    if errors:
        response["errors"] = errors
        return jsonify(response), 207 if uploaded_files else 400

    return jsonify(response), 200

@app.route('/upload_key_files', methods=['POST'])
def upload_key_files():
    # Validate the request has files under the key 'files'
    if 'files' not in request.files:
        return jsonify(error="No file part in the request"), 400

    files_keys = request.files.getlist('files')

    # Check if files list is empty or first file has an empty filename
    if not files_keys or files_keys[0].filename == "":
        return jsonify(error="No selected files"), 400

    uploaded_files = []
    errors = []

    for file in files_keys:
        filename = file.filename.lower()
        
        if file and is_valid_hash(filename):
            try:
                    # Upload file to S3 using file-like object
                s3_client.upload_fileobj(
                    Fileobj=file,
                    Bucket=BUCKET_NAME,
                    Key=KEY_PREFIX+filename
                )
                uploaded_files.append(filename)
            except Exception as e:
                errors.append({"filename": filename, "error": str(e)})
        else:
            errors.append({"filename": file.filename, "error": "Name is not a valid hash"})

    response = {"uploaded_files": uploaded_files}
    # If there are errors, include them in the response
    if errors:
        response["errors"] = errors
        return jsonify(response), 207 if uploaded_files else 400

    return jsonify(response), 200

@app.route('/list_backup_versions', methods=['POST'])
def list_backup_versions():
    if not request.is_json:
        return jsonify({"error": "Request data must be in JSON format"}), 400

    data = request.get_json()
    backup_name = data.get('backup')
    if not backup_name:
        return jsonify({"error": "Backup name not provided"}), 400

    backup_file = backup_name + '.json'

    paginator = s3_client.get_paginator('list_object_versions')
    version_infos = []
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=backup_file):
        for version in page.get('Versions', []):
            if version['Key'] == backup_file:
                version_infos.append({'version_id': version['VersionId'],
                                      'last_modified': version['LastModified']})
    return jsonify(version_infos)


def get_file(prefix, filename):
    if is_valid_hash(filename):
        try:
            file_data = s3_client.get_object(
                Bucket=BUCKET_NAME, Key=prefix+filename
            ).get('Body').read()
            return send_file(BytesIO(file_data), mimetype='application/octet-stream')
        except Exception as e:
            return jsonify(error=f"Error getting file '{filename}': {str(e)}"), 500
    else:
        return jsonify(error="Invalid filename"), 400


@app.route('/get_data_file/<filename>', methods=['GET'])
def get_data_file(filename):
    return get_file(HASHES_PREFIX, filename)

@app.route('/get_key_file/<filename>', methods=['GET'])
def get_key_file(filename):
    return get_file(KEY_PREFIX, filename)

@app.route('/get_meta_file', methods=['GET'])
def get_meta_file():
    backup_file = request.args.get('backup') + '.json'
    version = request.args.get('version')
    try:
        file_data = s3_client.get_object(
            Bucket=BUCKET_NAME, Key=backup_file, VersionId=version
        ).get('Body').read()
        return send_file(BytesIO(file_data), mimetype='application/octet-stream')
    except Exception as e:
        return jsonify(error=f"Error getting file '{backup_file}': {str(e)}"), 500

@app.route('/get_meta_key', methods=['GET'])
def get_meta_key():
    backup_name = request.args.get('backup')
    version = request.args.get('version')
    key_filename = backup_name + '_' + version + '.key'
    try:
        file_data = s3_client.get_object(
            Bucket=BUCKET_NAME, Key=key_filename
        ).get('Body').read()
        return send_file(BytesIO(file_data), mimetype='application/octet-stream')
    except Exception as e:
        return jsonify(error=f"Error getting file '{key_filename}': {str(e)}"), 500


if __name__ == '__main__':
    # Run the Flask application in debug mode
    app.run(debug=True)

