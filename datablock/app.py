import os
import hashlib
import json
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
import requests
from base64 import b64encode
from dotenv import load_dotenv
from botocore.config import Config
from botocore.exceptions import ClientError
from models import User, init_db

# Load environment variables
load_dotenv()

config = Config(
    region_name=os.getenv('AWS_REGION', 'ap-southeast-1'),
    signature_version='v4',
    retries={
        'max_attempts': 10,
        'mode': 'standard'
    }
)

UPLOAD_FOLDER = 'uploads'
PREPROCESSED_FOLDER = 'preprocessed'
ENCRYPTED_FOLDER = 'encrypted'
KEYS_FOLDER = 'keys'
HASHES_FOLDER = 'hashes'
HISTORY_FILE = 'upload_history.json'
ALLOWED_EXTENSIONS = {'txt', 'json', 'csv'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PREPROCESSED_FOLDER'] = PREPROCESSED_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['KEYS_FOLDER'] = KEYS_FOLDER
app.config['HASHES_FOLDER'] = HASHES_FOLDER
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY')
AWS_REGION = os.getenv('AWS_REGION', 'ap-southeast-1')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME', 'datasetstesting')

ETH_NETWORK_ID = os.getenv('ETH_NETWORK_ID')
ETH_NODE_ENDPOINT = os.getenv('ETH_NODE_ENDPOINT', 'https://nd-[your-node-id].ethereum.managedblockchain.[region].amazonaws.com')
ETH_ACCOUNT_ADDRESS = os.getenv('ETH_ACCOUNT_ADDRESS')
ETH_PRIVATE_KEY = os.getenv('ETH_PRIVATE_KEY')
ETH_CONTRACT_ADDRESS = os.getenv('ETH_CONTRACT_ADDRESS')

FILE_STORAGE_ABI = [
    {
        "inputs": [
            {"type": "string", "name": "fileHash"},
            {"type": "string", "name": "encryptionKey"},
            {"type": "string", "name": "fileName"}
        ],
        "name": "storeFileData",
        "outputs": [{"type": "bool", "name": "success"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"type": "string", "name": "fileHash"}],
        "name": "getFileData",
        "outputs": [
            {"type": "string", "name": "encryptionKey"},
            {"type": "string", "name": "fileName"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

s3 = boto3.client(
    's3', 
    config=config,
    region_name=os.getenv('AWS_REGION'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('AWS_SECRET_KEY')
)

from blockchain import store_in_blockchain, get_from_blockchain, validate_blockchain, get_blockchain_info

try:
    s3 = boto3.client(
        's3',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
except Exception as e:
    print(f"Error initializing AWS S3 client: {str(e)}")
    s3 = None

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_history():
    """Load upload history from JSON file."""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []

def save_history(history):
    """Save upload history to JSON file."""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_to_history(original_filename, encrypted_filename, file_hash, file_size=0, user_id=None):
    """Add a new upload record to history."""
    history = load_history()
    record = {
        'id': len(history) + 1,
        'user_id': user_id,
        'original_filename': original_filename,
        'encrypted_filename': encrypted_filename,
        'hash': file_hash,
        'file_size': file_size,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'date': datetime.now().strftime('%Y-%m-%d'),
        'time': datetime.now().strftime('%H:%M:%S')
    }
    history.append(record)
    save_history(history)
    return record

@app.route('/')
@login_required
def index():
    """Renders the file upload form."""
    return render_template('index.html')

@app.route('/history')
@login_required
def history():
    """Renders the upload history page."""
    return render_template('history.html')

@app.route('/decrypt-page')
@login_required
def decrypt_page():
    """Renders the decrypt page."""
    return render_template('decrypt.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Renders the login page and handles authentication."""
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember = data.get('remember', False)

        if not username or not password:
            return jsonify({'error': 'All fields are required'}), 400

        # Try to find user by username or email
        user = User.get_by_username(username)
        if not user:
            user = User.get_by_email(username)

        if user and user.check_password(password):
            login_user(user, remember=remember)
            return jsonify({'success': True, 'message': 'Logged in successfully!'}), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Renders the signup page and handles registration."""
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400

        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # Check if user already exists
        if User.get_by_username(username):
            return jsonify({'error': 'Username already exists'}), 400

        if User.get_by_email(email):
            return jsonify({'error': 'Email already exists'}), 400

        # Create user
        user = User.create(username, email, password)
        if user:
            login_user(user)
            return jsonify({'success': True, 'message': 'Account created successfully!'}), 200
        else:
            return jsonify({'error': 'Failed to create account'}), 500

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/reset')
def reset():
    """Renders the password reset page."""
    return render_template('reset.html')

@app.route('/api/history')
@login_required
def get_history():
    """API endpoint to get upload history for current user."""
    history = load_history()
    # Filter history for current user only
    user_history = [item for item in history if item.get('user_id') == current_user.id]
    return jsonify(user_history)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handles the file upload, hashing, and encryption."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        file_content_raw = file.read()
        
        original_filename = file.filename
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        with open(original_path, 'wb') as orig_file:
            orig_file.write(file_content_raw)
        
        key_seed = os.urandom(32) 
        aes_key = hashlib.sha256(key_seed).digest() 
        iv = os.urandom(16)
        
        key_data = aes_key.hex() + ":" + iv.hex() 
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_content_raw) + encryptor.finalize()
        
        encrypted_filename = f"encrypted_{file.filename}"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
        
        file_hash = hashlib.sha256(encrypted_data).hexdigest()
        
        hash_filename = f"{file.filename.split('.')[0]}.sha256"
        hash_path = os.path.join(app.config['HASHES_FOLDER'], hash_filename)
        with open(hash_path, 'w') as f:
            f.write(file_hash)
        
        try:
            if s3:
                print("Starting blockchain storage process...")
                
                blockchain_receipt = store_in_blockchain(
                    file_hash,
                    key_data,
                    original_filename
                )
                
                if not blockchain_receipt:
                    print("Failed to store data in blockchain. Aborting file upload.")
                    return jsonify({
                        'error': 'Failed to store hash and key in blockchain. Please try again.'
                    }), 500

                s3.upload_file(encrypted_path, S3_BUCKET_NAME, f"encrypted/{encrypted_filename}")
                print(f"Successfully uploaded encrypted file to S3 bucket: {S3_BUCKET_NAME}")
                print(f"Data successfully stored in blockchain:")
                print(f"  - Block Index: {blockchain_receipt.get('blockIndex', 'N/A')}")
                print(f"  - Block Hash: {blockchain_receipt.get('blockHash', 'N/A')}")
                print(f"  - Transaction ID: {blockchain_receipt['transactionId']}")
            else:
                print("Warning: S3 client not initialized. Files saved locally only.")
        except Exception as e:
            print(f"Error uploading to S3: {str(e)}")
        
        file_size = len(file_content_raw)
        add_to_history(original_filename, encrypted_filename, file_hash, file_size, current_user.id)

        try:
            if os.path.exists(original_path):
                os.remove(original_path)
                print(f"Original file deleted for security: {original_filename}")
        except Exception as e:
            print(f"Warning: Could not delete original file: {str(e)}")

        response_data = {
            'hash': file_hash,
            'message': f"File '{file.filename}' processed successfully!",
            'original_filename': original_filename,
            'encrypted_filename': encrypted_filename
        }

        if 'blockchain_receipt' in locals() and blockchain_receipt:
            response_data['blockchain'] = {
                'transaction_id': blockchain_receipt.get('transactionId'),
                'block_index': blockchain_receipt.get('blockIndex'),
                'block_hash': blockchain_receipt.get('blockHash'),
                'timestamp': blockchain_receipt.get('timestamp')
            }

        return jsonify(response_data), 200
    else:
        return jsonify({'error': 'Invalid file type. Only .txt, .json, and .csv are allowed.'}), 400

@app.route('/download/encrypted/<filename>')
def download_encrypted(filename):
    """Download the encrypted file."""
    try:
        file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt/<file_hash>')
def decrypt_file(file_hash):
    """Decrypt a file using its hash to retrieve the encryption key from blockchain."""
    try:
        print(f"Decryption request for hash: {file_hash}")

        blockchain_data = get_from_blockchain(file_hash)

        if not blockchain_data:
            return jsonify({'error': 'File hash not found in blockchain. Cannot decrypt.'}), 404

        encryption_key_data = blockchain_data['encryption_key']
        original_filename = blockchain_data['file_name']

        try:
            key_parts = encryption_key_data.split(':')
            aes_key = bytes.fromhex(key_parts[0])
            iv = bytes.fromhex(key_parts[1])
        except Exception as e:
            print(f"Error parsing encryption key: {str(e)}")
            return jsonify({'error': 'Invalid encryption key format'}), 500

        encrypted_filename = f"encrypted_{original_filename}"
        encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)

        if not os.path.exists(encrypted_path):
            return jsonify({'error': 'Encrypted file not found on server'}), 404

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_folder = 'decrypted'
        if not os.path.exists(decrypted_folder):
            os.makedirs(decrypted_folder)

        decrypted_path = os.path.join(decrypted_folder, original_filename)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        print(f"Successfully decrypted file: {original_filename}")

        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/blockchain/info')
@login_required
def blockchain_info():
    """Get blockchain information and statistics."""
    try:
        info = get_blockchain_info()
        return jsonify(info), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/validate')
@login_required
def blockchain_validate():
    """Validate blockchain integrity."""
    try:
        is_valid = validate_blockchain()
        return jsonify({
            'valid': is_valid,
            'message': 'Blockchain is valid!' if is_valid else 'Blockchain integrity check failed!'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test')
def test():
    """Test route to verify Flask is working."""
    return jsonify({
        'status': 'Flask is running!',
        'folders_exist': {
            'uploads': os.path.exists(UPLOAD_FOLDER),
            'encrypted': os.path.exists(ENCRYPTED_FOLDER),
            'keys': os.path.exists(KEYS_FOLDER),
            'hashes': os.path.exists(HASHES_FOLDER)
        },
        'blockchain': get_blockchain_info()
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" " * 20 + "DataBlock - Blockchain File Storage")
    print("="*70 + "\n")

    print("📁 Initializing directories...")
    for folder in [UPLOAD_FOLDER, PREPROCESSED_FOLDER, ENCRYPTED_FOLDER, KEYS_FOLDER, HASHES_FOLDER, 'decrypted']:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"  ✓ Created: {folder}/")
        else:
            print(f"  ✓ Found: {folder}/")

    print("\n💾 Initializing database...")
    init_db()

    print("\n🔗 Loading blockchain...") 

    print("\n" + "="*70)
    print("🚀 Flask application starting...")
    print("📡 Server: http://127.0.0.1:5000")
    print("="*70 + "\n")

    app.run(debug=True)

 