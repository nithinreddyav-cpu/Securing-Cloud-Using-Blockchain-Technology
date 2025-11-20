## 📋 wtf is this

DataBlock is a **blockchain-based encrypted file storage system** that demonstrates real blockchain principles including proof-of-work mining, cryptographic hashing, and chain validation. Files are encrypted using AES-256, stored in AWS S3 (or locally), while encryption keys and metadata are stored in a blockchain for security and immutability.

When presenting to teacher, just say its real shit not just simulation

say
This implements ALL core blockchain principles like
- Cryptographic hashing (SHA-256)
- Proof-of-work mining algorithm
- Block chaining with previous hash references
- Chain validation and immutability
- Genesis block creation
- Merkle tree-like data structure
The only difference from Bitcoin/Ethereum is:
- It's not distributed across a network (runs locally)
- No consensus algorithm needed (single authority)
- Stored in JSON instead of distributed ledger
This is similar to:
- Private/permissioned blockchains (like Hyperledger)
- Enterprise blockchain solutions
- Development blockchain environments (like Ganache)

---

## how it works though

### **3-Layer Security Model**

```
┌─────────────────────────────────────────────────────────┐
│                    USER UPLOADS FILE                    │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  1. ENCRYPTION LAYER (AES-256)                          │
│     - Generate random AES-256 key                       │
│     - Encrypt file with AES-256-CFB                     │
│     - Generate IV (Initialization Vector)               │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  2. HASHING LAYER (SHA-256)                             │
│     - Hash encrypted file → File Hash                   │
│     - Used as unique identifier                         │
└─────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────┬──────────────────────────────────┐
│  3a. BLOCKCHAIN      │  3b. STORAGE LAYER               │
│      (Keys & Hash)   │      (Encrypted File)            │
│                      │                                  │
│  Stores:             │  Stores:                         │
│  - File Hash         │  - Encrypted File                │
│  - Encryption Key    │                                  │
│  - IV (hex)          │  Location:                       │
│  - Filename          │  - AWS S3 (production)           │
│  - Timestamp         │  - Local /encrypted (dev)        │
│                      │                                  │
│  Format:             │                                  │
│  blockchain_         │                                  │
│  storage.json        │                                  │
└──────────────────────┴──────────────────────────────────┘
```

### but why this?

Blockchain = Immutable key storage (tamper-proof)
S3/Local = Bulk encrypted file storage
Need BOTH to decrypt (distributed security)
like imagine if theres an
Attacker with S3 access → Can't decrypt (no keys)
Attacker with blockchain → Can't read data (no encrypted files)
Blockchain tampering → Detected immediately (chain validation fails)



### **Block Structure**

```json
{
  "index": 2,
  "timestamp": "2025-10-17T10:00:40.199032",
  "data": {
    "type": "file_storage",
    "file_hash": "44359ddeba751180815cbd7b89e7ee7f95f0aa8db617e229e472dd667b5881dc",
    "encryption_key": "0e08446b39708889aaf3da4d977c8124994d8a00d0d6352591ff10cc611b62e6:7168653550906671b0bf9acff4dcd02f",
    "file_name": "test_sample.json",
    "timestamp": "2025-10-17T10:00:40.198625"
  },
  "previous_hash": "009d8e71f188ebbf87e934a3d3be6cfd94548be3343b0323012d0950e84b144c",
  "nonce": 429,
  "hash": "005470ccc634dd7d8cfd7cfc6499493e74721c5ecd1a55eb2d162fce2144700b"
}
```

### **Mining**

```python
# Mining Algorithm
difficulty = 2  # Requires 2 leading zeros
target = "00..."  # Hash must start with "00"

nonce = 0
while True:
    hash = SHA256(block_data + nonce)
    if hash.startswith(target):
        break  
    nonce += 1

# Example: nonce=429 produces hash "005470cc..."
```

### **Chain Validation**

The blockchain validates itself by checking:

1. **Hash Integrity**: Each block's hash matches its contents
2. **Chain Linking**: Each `previous_hash` matches the actual previous block's hash
3. **Proof-of-Work**: All hashes meet difficulty requirement (start with "00")

```python
# Validation Code
for i in range(1, len(chain)):
    current = chain[i]
    previous = chain[i-1]

    if current.hash != calculate_hash(current):
        return False

    if current.previous_hash != previous.hash:
        return False

    if not current.hash.startswith("00"):
        return False

return True 
```

```
If someone changes Block 1's data:
  → Block 1's hash changes
  → Block 2's previous_hash no longer matches
  → Validation FAILS
  → Tampering detected!
```

---

## Cryptography 

### **1. AES-256 Encryption (File Encryption)**

```
Algorithm: AES-256-CFB (Cipher Feedback Mode)
Key Size: 256 bits (32 bytes)
IV Size: 128 bits (16 bytes)
```
1. Generate random 32-byte key using `os.urandom(32)`
2. Hash with SHA-256 for additional randomness
3. Generate random 16-byte IV
4. Encrypt file: `AES256_CFB(file_data, key, iv)`

### **2. SHA-256 Hashing**

```
Algorithm: SHA-256 (Secure Hash Algorithm)
Output: 256-bit (64 hex characters)
Use Cases:
  - File hash generation
  - Block hash calculation
  - Proof-of-work mining
```

**Properties:**
- One-way function (can't reverse)
- Collision-resistant
- same input → same output
- tiny change → completely different hash

---


## **Step-by-Step Process of how the whole thing works in general**

```
1. User selects file (test.json)
   ↓
2. Server generates AES-256 key + IV
   ↓
3. Encrypt file → encrypted_test.json
   ↓
4. Hash encrypted file → SHA-256 hash
   ↓
5. CREATE BLOCKCHAIN BLOCK:
   - Start mining (find nonce)
   - Attempt 1, 2, 3... 429
   - Found! Hash starts with "00"
   ↓
6. Add block to chain
   ↓
7. Save encrypted file to S3/local
   ↓
8. Delete original file (security)
   ↓
9. Return hash to user
```


### File Decryption 

```
1. User enters file hash
   ↓
2. Query blockchain for hash
   ↓
3. Found in Block #2
   ↓
4. Retrieve:
   - Encryption key
   - IV
   - Original filename
   ↓
5. Fetch encrypted file from S3/local
   ↓
6. Decrypt using AES-256:
   AES256_CFB_DECRYPT(encrypted_data, key, iv)
   ↓
7. Send decrypted file to user
   ↓
8. Delete temporary decrypted file
```

---

## Technologies 

- **Python** - Backend language for easy blockchain implementation
- **Flask** - Lightweight web framework perfect for demos
- **SQLite** - Simple user database
- **Flask-Login** - Authentication system for user-specific file history
- **Cryptography** - library providing AES-256 encryption
- **Boto3** - AWS S3 integration for cloud file storage
- **JSON** - Human-readable blockchain storage format that's easy to validate
- **SHA-256** - Bitcoin/Ethereum standard hashing algorithm

---


If they ask if this is real blockchain just say,
Yes, it implements all core blockchain principles: cryptographic hashing, proof-of-work, chain linking, and validation. The only difference is it's not distributed across a network—it's a private blockchain, similar to enterprise solutions like Hyperledger.

Why not use actual Ethereum?
We can use it, The system is designed to work with AWS Managed Blockchain (Ethereum). For development, we use this local version for speed and cost. For production demos, we can deploy to a real Ethereum testnet or use Ganache for a local Ethereum environment.

---


### **Important Files**

- **blockchain_storage.json** - The actual blockchain containing all blocks that can be inspected and validated
- **blockchain.py** - Core blockchain implementation with Block/Blockchain classes, mining, and validation logic
- **app.py** - Main application handling file uploads, encryption, blockchain integration, and user authentication
