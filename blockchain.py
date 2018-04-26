import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

import Crypto
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Signature import PKCS1_v1_5 as Signer_PKCS1_v1_5

class Blockchain:
	def __init__(self):
		self.current_transactions = []
		self.chain = []
		self.nodes = set()

		# Create the genesis block
		self.new_block(previous_hash='1', proof=100)

	def register_node(self, address):
		"""
		Add a new node to the list of nodes

		:param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
		:return: None
		"""

		parsed_url = urlparse(address)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		elif parsed_url.path:
			# Accepts an URL without scheme like '192.168.0.5:5000'.
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')

	@staticmethod
	def valid_chain(chain):
		"""
		Determine if a given blockchain is valid

		:param chain: <list> A blockchain
		:return: <bool> True if valid, False if not
		"""

		last_block = chain[0]
		current_index = 1

		while current_index < len(chain):
			block = chain[current_index]
			# Check that the hash of the block is correct
			if block['previous_hash'] != Blockchain.hash(last_block):
				return False

			# Check that the Proof of Work is correct
			
			transactions_hash = hashlib.sha256(json.dumps(block['transactions'], sort_keys=True).encode() ).hexdigest()
			if not Blockchain.valid_proof(last_block['proof'], block['proof'], block['previous_hash'], transactions_hash):
				return False

			# Check that the transactions on this block are correct
			if not Blockchain.valid_transactions(block['transactions']):
				return False
			
			last_block = block
			current_index += 1

		return True

	def resolve_conflicts(self):
		"""
		This is our consensus algorithm, it resolves conflicts
		by replacing our chain with the longest one in the network.

		:return: <bool> True if our chain was replaced, False if not
		"""

		neighbours = self.nodes
		new_chain = None

		# We're only looking for chains longer than ours
		max_length = len(self.chain)

		# Grab and verify the chains from all the nodes in our network
		# Remove the ones that are not returning anything usefull
		invalidNodes = []
		for node in neighbours:
			try:
				response = requests.get('http://{:s}/chain'.format(str(node)), timeout=5)
	
				if response.status_code == 200:
					length = response.json()['length']
					chain = response.json()['chain']
					
					# Check if the length is longer and the chain is valid
					if length > max_length and Blockchain.valid_chain(chain):
						max_length = length
						new_chain = chain
			except Exception:
				invalidNodes.append(node)
		for node in invalidNodes:
			self.nodes.remove(node)
		
		# Replace our chain if we discovered a new, valid chain longer than ours
		if new_chain:
			self.chain = new_chain
			return True

		return False

	def new_block(self, proof, previous_hash=None):
		"""
		Create a new Block in the Blockchain

		:param proof: <int> The proof given by the Proof of Work algorithm
		:param previous_hash: (Optional) <str> Hash of previous Block
		:return: <dict> New Block
		"""
		block = {
			'index': len(self.chain) + 1,
			'timestamp': time(),
			'transactions': self.current_transactions,
			'proof': proof,
			'previous_hash': previous_hash or self.hash(self.chain[-1]),
		}
		# Reset the current list of transactions
		self.current_transactions = []

		self.chain.append(block)
		return block

	def new_transaction(self, sender, recipient, amount, signature):
		"""
		Creates a new transaction to go into the next mined Block

		:param sender: <str> Address of the Sender
		:param recipient: <str> Address of the Recipient
		:param amount: <int> Amount
		:return: <int> The index of the Block that will hold this transaction or -1, if the transaction is invalid.
		"""
		
		transaction = {
			'sender': sender,
			'recipient': recipient,
			'amount': amount,
			'signature': signature,
		}
		if Blockchain.valid_transaction(transaction):
			self.current_transactions.append(transaction)
			return self.last_block['index'] + 1
		else:
			return -1
	
	@staticmethod
	def hash(block):
		"""
		Creates a SHA-256 hash of a Block

		:param block: <dict> Block
		:return: <str>
		"""

		# We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
		block_string = json.dumps(block, sort_keys=True).encode()
		return hashlib.sha256(block_string).hexdigest()
		
	@staticmethod
	def valid_transaction(transaction):
		"""
		Determine if a given transactions is valid (i.e. if it has the zero sender or if it is signed with the private key of the sender)
		:param transaction: <dict> a transaction
		:return: <bool> True if valid, False if not
		"""
		if transaction['sender'] == "0":
			return True
		signed = '{amount='+str(transaction['amount'])+'|recipient='+str(transaction['recipient'])+'|sender='+str(transaction['sender'])+'}'
		verifier = Signer_PKCS1_v1_5.new(RSA.importKey(b64decode(transaction['sender'])))
		digest = Crypto.Hash.SHA256.new()
		digest.update(signed.encode())
		try:
			isValid = verifier.verify(digest, b64decode(transaction['signature']))
			if not isValid:
				raise ValueError
		except (ValueError, TypeError):
			return False
		
		return True
	
	@staticmethod
	def valid_transactions(transactions):
		"""
		Determine if a given list of transactions is valid
		:param transactions: <list> a list of transactions
		:return: <bool> True if valid, False if not
		"""
		numPayOffs = 0
		for transaction in transactions:
			if not Blockchain.valid_transaction(transaction):
				return False
			if transaction['sender'] == "0":
				numPayOffs += 1
		return (numPayOffs == 1)
	
	@property
	def last_block(self):
		# Returns the last Block in the chain
		return self.chain[-1]

	def proof_of_work(self, last_proof, last_hash, transactions_hash):
		"""
		Simple Proof of Work Algorithm:

		 - Find a number p' such that hash(pp'ht) contains leading 4 zeroes, where p is the previous p'
		 - p is the previous proof, and p' is the new proof
		 - h is the previous hash
		 - t is the hash of all transactions in this block
		:param last_proof: <int>
		:param last_hash: <string> Hash of last block
		:param transactions_hash: <string> Hash of the transactions in the current block
		:return: <int>
		"""
		proof = 0
		while self.valid_proof(last_proof, proof, last_hash, transactions_hash) is False:
			proof += 1

		return proof


	@staticmethod
	def valid_proof(last_proof, proof, last_hash, transactions_hash):
		"""
		Validates the Proof: Does hash(last_proof, proof, last_hash) contain 4 leading zeroes?

		:param last_proof: <int> Previous Proof
		:param proof: <int> Current Proof
		:param last_hash: <str> The hash of the previous Block
		:param transactions_hash: <string> Hash of the transactions in the current block
		:return: <bool> True if correct, False if not.
		"""

		guess = '{:d}{:d}{:s}{:s}'.format(last_proof,proof,last_hash,transactions_hash).encode()
		guess_hash = hashlib.sha256(guess).hexdigest()
		return guess_hash[:4] == "0000"

	

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
	# We run the proof of work algorithm to get the next proof...
	last_block = blockchain.last_block
	last_proof = last_block['proof']
	previous_hash = blockchain.hash(last_block)
	
	# We must receive a reward for finding the proof.
	# The sender is "0" to signify that this node has mined a new coin.
	blockchain.new_transaction(
		sender="0",
		recipient=node_identifier,
		amount=1,
		signature="true"
	)

	transactions_hash = hashlib.sha256( json.dumps(blockchain.current_transactions, sort_keys=True).encode() ).hexdigest()
	proof = blockchain.proof_of_work(last_proof, previous_hash, transactions_hash)
	
	# Forge the new Block by adding it to the chain
	block = blockchain.new_block(proof, previous_hash)

	response = {
		'message': "New Block Forged",
		'index': block['index'],
		'transactions': block['transactions'],
		'proof': block['proof'],
		'previous_hash': block['previous_hash'],
	}
	return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
	values = request.get_json()

	# Check that the required fields are in the POST'ed data
	required = ['sender', 'recipient', 'amount', 'signature']
	if not all(k in values for k in required):
		return 'Missing values', 400

	# Create a new Transaction
	index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['signature'])

	if (index > 0):
		response = {'message': 'Transaction will be added to Block {:d}'.format(index)}
		return jsonify(response), 201
	else:
		return 'Invalid values', 400


@app.route('/chain', methods=['GET'])
def full_chain():
	response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain),
	}
	return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
	values = request.get_json()

	nodes = values.get('nodes')
	if nodes is None:
		return "Error: Please supply a valid list of nodes", 400

	for node in nodes:
		blockchain.register_node(node)

	response = {
		'message': 'New nodes have been added',
		'total_nodes': list(blockchain.nodes),
	}
	return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
	replaced = blockchain.resolve_conflicts()

	if replaced:
		response = {
			'message': 'Our chain was replaced',
			'new_chain': blockchain.chain
		}
	else:
		response = {
			'message': 'Our chain is authoritative',
			'chain': blockchain.chain
		}

	return jsonify(response), 200


if __name__ == '__main__':
	from argparse import ArgumentParser

	parser = ArgumentParser()
	parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
	parser.add_argument('-a', '--address', default='0.0.0.0', type=str, help='ip-address of the blockchain-servers\'s host')
	args = parser.parse_args()
	port = args.port
	host= args.address
	
	app.run(host=host, port=port)
