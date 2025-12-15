# 🔐 Securing Cloud Using Blockchain Technology

## Project Overview
Securing Cloud Using Blockchain Technology is a secure cloud file storage system that integrates cryptography, blockchain technology, and cloud computing to ensure data confidentiality, integrity, and tamper-proof metadata storage. Files are encrypted before cloud upload, while encryption keys and file metadata are stored immutably in a custom blockchain ledger.

---

## Problem Statement
Traditional cloud storage systems rely on centralized architectures to manage data and encryption keys. If the cloud infrastructure or key management system is compromised, sensitive data can be accessed, modified, or deleted without detection. Additionally, there is no transparent or tamper-proof mechanism to verify data integrity.

---

## Proposed Solution
The proposed system secures cloud storage by:
- Encrypting files using AES-256 symmetric encryption
- Generating SHA-256 hashes to verify data integrity
- Storing encryption keys, initialization vectors (IVs), and file hashes in a Proof-of-Work blockchain
- Uploading only encrypted files to cloud storage (AWS S3)

This ensures that even if cloud storage is compromised, the data remains unreadable and verifiable.

---

## System Architecture
User  
↓  
Flask Backend  
↓  
AES-256 Encryption & SHA-256 Hashing  
↓  
Blockchain (Key & Metadata Storage)  
↓  
Encrypted File Upload to AWS S3  

---

## Security Mechanisms
- *AES-256 Encryption:* Ensures data confidentiality  
- *SHA-256 Hashing:* Ensures data integrity verification  
- *Proof-of-Work Blockchain:* Prevents metadata tampering  
- *Secure Key Storage:* Encryption keys and IVs are stored immutably in the blockchain  
- *Authentication:* Implemented using Flask-Login  

---

## Blockchain Implementation
A custom blockchain is implemented using Python with Proof-of-Work consensus.  
Each block contains:
- File hash
- AES encryption key
- Initialization Vector (IV)
- Filename
- Timestamp
- Previous block hash
- Nonce
- Current block hash  

This design guarantees immutability, transparency, and traceability.

---

## Cloud Storage
Encrypted files are stored in AWS S3.  
The cloud never stores:
- Plaintext data  
- Encryption keys  
- Initialization vectors  

Even in the event of a cloud breach, stored files remain unreadable.

---

## Workflow

### File Upload
1. User uploads a file
2. File is encrypted using AES-256 with a random IV
3. SHA-256 hash of encrypted data is generated
4. Hash, AES key, and IV are stored in the blockchain
5. Encrypted file is uploaded to AWS S3
6. Original file is removed from local storage

### File Decryption
1. User provides file hash
2. Blockchain retrieves AES key and IV
3. Encrypted file is decrypted using AES-256
4. Original file is restored securely

---

## Technologies Used
- *Backend:* Python, Flask, Flask-Login  
- *Security:* AES-256, SHA-256  
- *Blockchain:* Custom Python Blockchain, Proof-of-Work  
- *Cloud:* AWS S3, boto3  

---

## Project Structure
- app.py  
- blockchain.py  
- blockchain_storage.json  
- upload_history.json  
- encrypted/  
- uploads/  
- hashes/  
- templates/  
- static/  

---

## Advantages
- Strong data confidentiality  
- Tamper-proof metadata storage  
- Secure encryption key management  
- Cloud-independent security model  
- Auditability and traceability  

---

## Limitations
- Single-node blockchain architecture  
- Proof-of-Work introduces computational overhead  

---

## Future Scope
- Multi-node distributed blockchain implementation  
- Integration with Ethereum or Hyperledger  
- Role-based access control  
- Two-factor authentication  
- React-based frontend integration  