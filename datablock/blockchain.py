import hashlib
import json
import time
from datetime import datetime
import os

BLOCKCHAIN_FILE = 'blockchain_storage.json'

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_success(message):
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

def print_info(message):
    print(f"{Colors.CYAN}ℹ {message}{Colors.ENDC}")

def print_warning(message):
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")

def print_error(message):
    print(f"{Colors.RED}✗ {message}{Colors.ENDC}")

def print_header(message):
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{message.center(60)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

class Block:
    """Represents a single block in the blockchain"""

    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data 
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculate SHA-256 hash of the block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty=2):
        """Mine the block with proof-of-work (difficulty = number of leading zeros)"""
        target = "0" * difficulty
        start_time = time.time()

        print_info(f"Mining block #{self.index}... (difficulty: {difficulty})")

        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

            if self.nonce % 100 == 0:
                print(f"{Colors.YELLOW}  ⛏  Attempt {self.nonce}... {Colors.ENDC}", end='\r')

        elapsed = time.time() - start_time
        print(f"\n{Colors.GREEN}  ✓ Block mined successfully!{Colors.ENDC}")
        print(f"{Colors.CYAN}  → Hash: {Colors.BOLD}{self.hash}{Colors.ENDC}")
        print(f"{Colors.CYAN}  → Nonce: {Colors.BOLD}{self.nonce}{Colors.ENDC}")
        print(f"{Colors.CYAN}  → Time: {Colors.BOLD}{elapsed:.2f}s{Colors.ENDC}\n")

    def to_dict(self):
        """Convert block to dictionary for JSON storage"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(block_dict):
        """Create Block object from dictionary"""
        block = Block(
            block_dict['index'],
            block_dict['timestamp'],
            block_dict['data'],
            block_dict['previous_hash'],
            block_dict['nonce']
        )
        block.hash = block_dict['hash']
        return block


class Blockchain:
    """Manages the blockchain"""

    def __init__(self, difficulty=2):
        self.chain = []
        self.difficulty = difficulty
        self.load_chain()

        if len(self.chain) == 0:
            self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block in the blockchain"""
        print_header("CREATING GENESIS BLOCK")

        genesis_block = Block(
            index=0,
            timestamp=datetime.now().isoformat(),
            data={
                "type": "genesis",
                "message": "DataBlock Genesis Block",
                "created": datetime.now().isoformat()
            },
            previous_hash="0"
        )
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        self.save_chain()

        print_success("Genesis block created and added to chain!")

    def get_latest_block(self):
        """Get the most recent block in the chain"""
        return self.chain[-1] if len(self.chain) > 0 else None

    def add_block(self, data):
        """Add a new block to the blockchain"""
        print_header("ADDING NEW BLOCK TO CHAIN")

        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now().isoformat(),
            data=data,
            previous_hash=latest_block.hash if latest_block else "0"
        )

        print_info(f"Previous block hash: {latest_block.hash[:16]}..." if latest_block else "No previous block")

        new_block.mine_block(self.difficulty)

        self.chain.append(new_block)
        self.save_chain()

        print_success(f"Block #{new_block.index} added to blockchain!")
        print_info(f"Total blocks in chain: {len(self.chain)}")

        return new_block

    def is_chain_valid(self):
        """Validate the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid hash at block {i}")
                return False

            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid previous hash at block {i}")
                return False

            if not current_block.hash.startswith("0" * self.difficulty):
                print(f"Invalid proof-of-work at block {i}")
                return False

        return True

    def save_chain(self):
        """Save blockchain to JSON file"""
        chain_data = {
            "difficulty": self.difficulty,
            "chain": [block.to_dict() for block in self.chain],
            "last_updated": datetime.now().isoformat()
        }
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(chain_data, f, indent=2)

    def load_chain(self):
        """Load blockchain from JSON file"""
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, 'r') as f:
                    chain_data = json.load(f)
                    self.difficulty = chain_data.get('difficulty', 2)
                    self.chain = [Block.from_dict(block_dict) for block_dict in chain_data.get('chain', [])]

                    print_success(f"Blockchain loaded: {len(self.chain)} blocks")
                    print_info(f"Difficulty: {self.difficulty}")
                    if len(self.chain) > 0:
                        print_info(f"Latest block: #{self.chain[-1].index} ({self.chain[-1].hash[:16]}...)")
            except Exception as e:
                print_error(f"Error loading blockchain: {str(e)}")
                self.chain = []
        else:
            self.chain = []

    def get_block_by_file_hash(self, file_hash):
        """Find a block containing data for a specific file hash"""
        for block in self.chain:
            if isinstance(block.data, dict) and block.data.get('file_hash') == file_hash:
                return block
        return None

    def store_file_data(self, file_hash, encryption_key, file_name):
        """Store file data in a new block"""
        data = {
            "type": "file_storage",
            "file_hash": file_hash,
            "encryption_key": encryption_key,
            "file_name": file_name,
            "timestamp": datetime.now().isoformat()
        }

        block = self.add_block(data)

        return {
            "success": True,
            "block_index": block.index,
            "block_hash": block.hash,
            "transaction_id": block.hash[:16],  
            "timestamp": block.timestamp
        }

    def retrieve_file_data(self, file_hash):
        """Retrieve file data from blockchain"""
        block = self.get_block_by_file_hash(file_hash)

        if block:
            return {
                "file_hash": block.data.get('file_hash'),
                "encryption_key": block.data.get('encryption_key'),
                "file_name": block.data.get('file_name'),
                "block_index": block.index,
                "block_hash": block.hash,
                "timestamp": block.timestamp
            }
        return None

    def get_chain_info(self):
        """Get blockchain statistics"""
        return {
            "total_blocks": len(self.chain),
            "difficulty": self.difficulty,
            "is_valid": self.is_chain_valid(),
            "latest_block_hash": self.get_latest_block().hash if self.get_latest_block() else None,
            "genesis_block_hash": self.chain[0].hash if len(self.chain) > 0 else None
        }


blockchain = Blockchain(difficulty=2)


def store_in_blockchain(file_hash, encryption_key, file_name):
    """Store file data in blockchain (wrapper function)"""
    try:
        print_info(f"Storing data in blockchain for file: {file_name}")
        print_info(f"File hash: {file_hash[:32]}...")

        result = blockchain.store_file_data(file_hash, encryption_key, file_name)

        if result['success']:
            print_success(f"Data stored in block #{result['block_index']}")
            print_info(f"Transaction ID: {result['transaction_id']}")

            return {
                'transactionId': result['transaction_id'],
                'blockIndex': result['block_index'],
                'blockHash': result['block_hash'],
                'status': 'success',
                'timestamp': result['timestamp']
            }
        return None
    except Exception as e:
        print_error(f"Error storing in blockchain: {str(e)}")
        return None


def get_from_blockchain(file_hash):
    """Retrieve file data from blockchain (wrapper function)"""
    try:
        print_header("QUERYING BLOCKCHAIN")
        print_info(f"Searching for file hash: {file_hash[:32]}...")

        result = blockchain.retrieve_file_data(file_hash)

        if result:
            print_success(f"Data found in block #{result['block_index']}")
            print_info(f"File name: {result['file_name']}")
            print_info(f"Block hash: {result['block_hash'][:32]}...")

            return {
                'encryption_key': result['encryption_key'],
                'file_name': result['file_name'],
                'hash': result['file_hash'],
                'block_index': result['block_index'],
                'block_hash': result['block_hash']
            }
        else:
            print_warning(f"File hash not found in blockchain")
            return None
    except Exception as e:
        print_error(f"Error retrieving from blockchain: {str(e)}")
        return None


def validate_blockchain():
    """Validate the blockchain integrity"""
    print_header("VALIDATING BLOCKCHAIN")

    is_valid = blockchain.is_chain_valid()

    if is_valid:
        print_success("Blockchain integrity check passed!")
        print_info(f"All {len(blockchain.chain)} blocks are valid")
    else:
        print_error("Blockchain integrity check failed!")

    return is_valid


def get_blockchain_info():
    """Get blockchain information"""
    info = blockchain.get_chain_info()

    print_header("BLOCKCHAIN INFORMATION")
    print_info(f"Total blocks: {info['total_blocks']}")
    print_info(f"Difficulty: {info['difficulty']}")
    print_info(f"Chain valid: {info['is_valid']}")
    if info['genesis_block_hash']:
        print_info(f"Genesis hash: {info['genesis_block_hash'][:32]}...")
    if info['latest_block_hash']:
        print_info(f"Latest hash: {info['latest_block_hash'][:32]}...")

    return info
