import abc
import base64
import os
import os.path
import struct
from dataclasses import dataclass, astuple
from typing import *

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, Hash

PRIVATE_KEY_ENCRYPTION_PASSWORD = b'passworrrrd'
PRIVATE_KEY_PATH = '~/.cctf2019_blockchain_wallet'
HASH_DIFFICULTY = 6
BLOCK_REWARD = 10_0000_0000


class Serializable(abc.ABC):
    @abc.abstractmethod
    def to_bytes(self, b: bytearray):
        pass

    @staticmethod
    @abc.abstractmethod
    def from_bytes(b: memoryview) -> Tuple[Any, memoryview]:
        pass


@dataclass()
class UTXORef(Serializable):
    block_hash: bytes
    index: int

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!32sH')

    def to_bytes(self, b: bytearray):
        b.extend(UTXORef.FORMAT.pack(*astuple(self)))

    @staticmethod
    def from_bytes(b: memoryview):
        return UTXORef(*UTXORef.FORMAT.unpack_from(b)), b[UTXORef.FORMAT.size:]


@dataclass()
class UTXO(Serializable):
    amount: int
    recipient: bytes

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q88s')

    def to_bytes(self, b: bytearray):
        b.extend(UTXO.FORMAT.pack(*astuple(self)))

    @staticmethod
    def from_bytes(b: memoryview):
        return UTXO(*UTXO.FORMAT.unpack_from(b)), b[UTXO.FORMAT.size:]


@dataclass()
class Transaction(Serializable):
    payer: bytes
    inputs: List[UTXORef]
    outputs: List[UTXO]
    signature: bytes = b''

    HEADER_FORMAT: ClassVar[struct.Struct] = struct.Struct('!88sHH')

    def to_signature_data(self) -> bytearray:
        b = bytearray(
            Transaction.HEADER_FORMAT.pack(self.payer, len(self.inputs), len(self.outputs)))
        for txn_input in self.inputs:
            txn_input.to_bytes(b)
        for txn_output in self.outputs:
            txn_output.to_bytes(b)
        return b

    def verify_signature(self) -> bool:
        public_key = serialization.load_der_public_key(self.payer,
                                                       default_backend())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        try:
            public_key.verify(self.signature, self.to_signature_data(),
                              ec.ECDSA(SHA256()))
            return True
        except InvalidSignature:
            return False

    def to_bytes(self, b: bytearray):
        b.extend(self.to_signature_data())
        r, s = decode_dss_signature(self.signature)
        b.extend(r.to_bytes(32, byteorder='big'))
        b.extend(s.to_bytes(32, byteorder='big'))

    @staticmethod
    def from_bytes(b: memoryview):
        payer, input_len, output_len = Transaction.HEADER_FORMAT.unpack_from(b, 0)
        b = b[Transaction.HEADER_FORMAT.size:]
        inputs = []
        outputs = []
        for i in range(input_len):
            txn_input, b = UTXORef.from_bytes(b)
            inputs.append(txn_input)
        for i in range(output_len):
            txn_output, b = UTXO.from_bytes(b)
            outputs.append(txn_output)
        rb, sb = b[:32], b[32:64]
        r = int.from_bytes(rb, byteorder='big')
        s = int.from_bytes(sb, byteorder='big')
        return Transaction(payer=payer, inputs=inputs, outputs=outputs, signature=encode_dss_signature(r, s)), b[64:]


@dataclass()
class Wallet:
    public_key: ec.EllipticCurvePublicKey
    private_key: ec.EllipticCurvePrivateKeyWithSerialization

    def serialize_public(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

    def to_address(self) -> bytes:
        return base64.urlsafe_b64encode(self.serialize_public())

    def create_transaction(self, inputs: List[UTXORef], outputs: List[UTXO]) -> Transaction:
        txn = Transaction(payer=self.serialize_public(), inputs=inputs, outputs=outputs)
        txn.signature = self.private_key.sign(txn.to_signature_data(),
                                              ec.ECDSA(SHA256()))
        return txn

    def save_to_disk(self):
        s = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization.BestAvailableEncryption(
                                               PRIVATE_KEY_ENCRYPTION_PASSWORD))
        with open(os.path.expanduser(PRIVATE_KEY_PATH), 'wb') as f:
            f.write(s)

    @staticmethod
    def load_from_disk():
        try:
            with open(os.path.expanduser(PRIVATE_KEY_PATH), 'rb') as f:
                s = f.read()
        except FileNotFoundError:
            return None
        loaded = serialization.load_pem_private_key(s,
                                                    password=PRIVATE_KEY_ENCRYPTION_PASSWORD,
                                                    backend=default_backend())
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            os.unlink(os.path.expanduser(PRIVATE_KEY_PATH))
            return None
        else:
            return Wallet(public_key=loaded.public_key(), private_key=loaded)

    @staticmethod
    def new():
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()
        w = Wallet(public_key=public_key, private_key=private_key)
        assert len(w.serialize_public()) == 88
        return w


@dataclass()
class Block(Serializable):
    transactions: List[Transaction]
    nonce: int = 0
    parent_hash: bytes = b'\x00' * 32
    block_hash: bytes = b'\x00' * 32

    HEADER_FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q32sL')

    def to_hash_challenge(self) -> bytearray:
        b = bytearray(Block.HEADER_FORMAT.pack(self.nonce, self.parent_hash, len(self.transactions)))
        for t in self.transactions:
            t.to_bytes(b)
        return b

    def solve_hash_challenge(self, difficulty: int = HASH_DIFFICULTY, max_tries=None):
        b = self.to_hash_challenge()
        if max_tries is None:
            max_tries = 1 << 64
        while max_tries > 0:
            max_tries -= 1
            digest = Hash(SHA256(), default_backend())
            digest.update(b)
            this_hash = digest.finalize()
            if this_hash[:difficulty] == b'\x00' * difficulty:
                self.block_hash = this_hash
                return
            else:
                self.nonce += 1
                self.nonce %= 1 << 64
                struct.pack_into('!Q', b, 0, self.nonce)

    def to_bytes(self, b: bytearray):
        b.extend(self.to_hash_challenge())
        b.extend(self.block_hash)

    @staticmethod
    def from_bytes(b: memoryview):
        nonce, parent_hash, transactions_len = Block.HEADER_FORMAT.unpack_from(b)
        b = b[Block.HEADER_FORMAT.size:]
        transactions = []
        for i in range(transactions_len):
            txn, b = Transaction.from_bytes(b)
            transactions.append(txn)
        block_hash = b[:32]
        return Block(transactions=transactions, nonce=nonce, parent_hash=parent_hash, block_hash=block_hash), b[32:]
