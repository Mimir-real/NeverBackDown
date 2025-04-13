import re
from os.path import basename
from flask import Flask, request, jsonify, redirect, url_for, flash
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)

# S3 configuration variables
BUCKET_NAME = 'backuper-1'  # Replace with your S3 bucket name
HASHES_PREFIX = 'hash_files/'
s3_client = boto3.client('s3')

def get_s3_hashes():
    """
    Retrieves a list of file names (hashes) from S3 bucket.
    """
    hashes = set()

    paginator = s3_client.get_paginator('list_objects_v2')
    # Paginate through all objects in the bucket (and optionally filter by prefix)
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=HASHES_PREFIX):
        objects = page.get('Contents', [])
        for obj in objects:
            # Assuming that the object key represents a hash
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
        return jsonify({"error": "Couldn't receive S3 objects"})

    # Compute the difference; only include those hashes from the client that are not in S3
    missing_hashes = client_hashes - s3_hashes

    # Return the result as JSON
    return jsonify({"missing_hashes": list(missing_hashes)}), 200

@app.route('/upload_meta_file', methods=['POST'])
def upload_meta_file():
    if 'file' not in request.files:
        return jsonify(error="No file part in the request"), 400

    file = request.files['file']

    # Check if a file was actually selected
    if file.filename == "":
        return jsonify(error="No file selected"), 400

    # Sanitize the filename
    filename = basename(file.filename) + '.json'

    try:
        # Upload file directly to S3
        s3_client.upload_fileobj(
            Fileobj=file,
            Bucket=BUCKET_NAME,
            Key=filename
        )
        return jsonify(message=f"File '{filename}' uploaded successfully to S3."), 200

    except Exception as e:
        # Return an error response if S3 upload fails
        return jsonify(error=f"Error uploading file '{filename}': {str(e)}"), 500

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
                    Key=HASHES_PREFIX+filename  # Customize key or path in your S3 bucket as needed
                )
                uploaded_files.append(filename)
            except Exception as e:
                # Append S3 upload exception error along with filename info
                errors.append({"filename": filename, "error": str(e)})
        else:
            errors.append({"filename": file.filename, "error": "Name is not a valid hash"})

    response = {"uploaded_files": uploaded_files}
    # If there are errors, include them in the response
    if errors:
        response["errors"] = errors
        # Optionally, you can choose the status code based on your needs.
        # Here, 207 (Multi-Status) can indicate a partial success, or 400 if you consider any error as failure.
        return jsonify(response), 207 if uploaded_files else 400

    return jsonify(response), 200


if __name__ == '__main__':
    # Run the Flask application in debug mode
    app.run(debug=True)


