import hashlib, random

def hash(data):						
	_encoded = data.encode()          # Converting the string to a byte array
	_hash = hashlib.sha256(_encoded)  # Hashing byte array (Byte Array -> Byte Array)
									  # For demonstration purposes sha256 is used
									  # Any hash could be used, but sha256 is guaranteed by
									  # python to be delivered to be possible on every machine.
	_digest = _hash.hexdigest()		  # Converts byte array to hexadecimal numbers (string)
	return (_digest)


def validate_block_hash(_hash, difficulty):
	_hash_int = int(_hash,16)              # Converting the hash to an (unsigned) integer 
	if (_hash_int * difficulty < 2**256):  # See if the hash meets the difficulty requirements
										   # as proposed in the cryptonote papers
										   # Paper about Difficulty Adjustment:
										   # https://cryptonote.org/cns/cns010.txt
		return True
	return False


def proof_of_work(block_header, block_data, difficulty, debug):
	while True:
		_current_block_header = block_header                     # Copying header data to a usable variable
		nonce = random.randint(0,2**32)					         # Generating nonce
														         # For bitcoin, its a maximum of 2**32
														         # You can swap transactions, change
														         # timestamps, etc. so you can still get
														         # many more different hash values than
														         # you have values for a nonce
														         # more on that here:
														         # https://bitcoin.stackexchange.com/questions/1781/nonce-size-will-it-always-be-big-enough
		_current_block_header = _current_block_header + '\n  "nonce": {:d}\n'.format(nonce)
																 # Adding nonce to current block header
		_current_block_data = _current_block_header + block_data # Assembling the Block
		_hash = hash(_current_block_data)                        # Getting hash of current block header
		if(validate_block_hash(_hash, difficulty)):			     # If hash meets requirements, stop trying
			break
	return(_current_block_data)



if __name__ == "__main__":
	import sys
	block_header = r"""{
  "major_version": 1, 
  "minor_version": 1, 
  "timestamp": 1526159241, 
  "prev_id": "8db212b1d25db5727a982926d0dcb4cad0f4a4141c1fa83d61af656330d1c2fd", """
	block_data = """  "miner_tx": {
    "version": 1, 
    "unlock_time": 100060, 
    "vin": [ {
        "gen": {
          "height": 100000
        }
      }
    ], 
    "vout": [ {
        "amount": 3331344399956, 
        "target": {
          "key": "d60e79c216832a73f49f5fa666de3632066935ea2933060daef370f3f2d38819"
        }
      }
    ], 
    "extra": [ 1, 19, 58, 65, 111, 182, 246, 80, 122, 244, 148, 98, 16, 41, 47, 140, 49, 157, 160, 51, 221, 90, 143, 143, 79, 36, 231, 212, 211, 158, 139, 242, 149, 2, 17, 0, 0, 0, 70, 148, 160, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ], 
    "rct_signatures": {
      "type": 0
    }
  }, 
  "tx_hashes": [ "8eb3584a788c94edd4baef6211cba0882024ba3150affa89e28427358b7780cd"
  ]
}"""

	try:
		difficulty = int(sys.argv[1])%2**32
	except:
		difficulty = 2**10

	try:
		debug = bool(int(sys.argv[2])%2)
	except:
		debug = False
	
	_current_block_data = proof_of_work(block_header, block_data, difficulty, debug)
	print(_current_block_data)
	print('\n\nHash: {:s}'.format(hash(_current_block_data)))
