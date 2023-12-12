import pickle, os
import ecdsa, hashlib
from Crypto.Hash import keccak

DEFAULT_TARGET = "./keypair.pem"

class SECP256k1:
    def __init__(self, target=DEFAULT_TARGET):
        self.target = target
    def store(self, data):
        with open(self.target, 'wb') as f:
            pickle.dump(data, f)
    def load(self):
        with open(self.target, 'rb') as f:
            data = pickle.load(f)
            return {
                "private_key": data["private_key"],
                "public_key_x": data["public_key_x"],
                "public_key_y": data["public_key_y"],
                "public_key_hex": data["public_key_hex"],
                "public_key_hex_compressed": data["public_key_hex_compressed"],
                "public_evm_address": data["public_evm_address"]
            }
    def new(self):
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        public_key_hex_uncompressed = public_key.to_string("uncompressed").hex()
        public_key_hex_compressed = public_key.to_string("compressed").hex()
        x_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[1:33])
        y_coordinate_bytes = list(bytes.fromhex(public_key_hex_uncompressed)[33:])
        public_evm_address = self.public_key_to_eth_address(public_key_hex_uncompressed)

        return {
            "private_key": private_key,
            "public_key_x": x_coordinate_bytes,
            "public_key_y": y_coordinate_bytes,
            "public_key_hex": public_key_hex_uncompressed,
            "public_key_hex_compressed": public_key_hex_compressed,
            "public_evm_address": public_evm_address
        }
    def sign(self, message):
        data = self.load()
        private_key = data["private_key"]

        user_msg = message + " " + data["public_evm_address"]
        # hash the message and sign the hash
        message_hash = hashlib.sha256(user_msg.encode('utf-8')).hexdigest()
        message_bytes = bytes.fromhex(message_hash)
        signature = private_key.sign_deterministic(
            message_bytes, 
            extra_entropy=b"",
            # hash the message hash (2x sha256)
            hashfunc=hashlib.sha256
        )
        return {
            "message": message_bytes,
            "signature": signature
        }
    def sign_and_print(self, message):
        data = self.sign(message)
        print("Message: ", list(data["message"]))
        print("Signature: ", list(bytes.fromhex(data["signature"].hex())))
        keys = self.load()
        print("X coordinate: ", keys["public_key_x"])
        print("Y coordinate: ", keys["public_key_y"])
        print("Hex Public Uncompressed: ", keys["public_key_hex"])
        print("Hex Public Compressed: ", keys["public_key_hex_compressed"])
        print("Ethereum Address: ", keys["public_evm_address"])

    def public_key_to_eth_address(self, public_key_hex):
        # Decode the hex public key to bytes
        public_key_bytes = bytes.fromhex(public_key_hex[2:])  # Skip the '04' prefix
        # Hash the public key using Keccak-256
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(public_key_bytes)
        # Take the last 20 bytes of the hash and convert to hex
        address = keccak_hash.digest()[-20:].hex()
        return "0x" + address




if not os.path.exists(DEFAULT_TARGET):
    open(DEFAULT_TARGET, 'x')
secp = SECP256k1()
# create new keypair and save at DEFAULT_TARGET
# secp.store(secp.new())
# sign an oversimplified transaction
secp.sign_and_print("I own this address: ")
