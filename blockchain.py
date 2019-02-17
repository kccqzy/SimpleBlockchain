import binascii
import os
import os.path
import struct
from dataclasses import dataclass, astuple
from typing import *

from cryptography.hazmat.primitives.asymmetric.utils import \
    decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash

PRIVATE_KEY_ENCRYPTION_PASSWORD = b'passworrrrd'
PRIVATE_KEY_PATH = '~/.cctf2019_blockchain_wallet'
HASH_DIFFICULTY = 6
BLOCK_REWARD = 10_0000_0000


@dataclass()
class Transaction:
    amount: int
    payer: bytes
    payee: bytes
    signature: bytes = b''

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q88s88s32s32s')

    def to_signature_data(self) -> bytes:
        return struct.pack('!QHH', self.amount, len(self.payer),
                           len(self.payee)) + self.payer + self.payee

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

    def to_bytes(self) -> bytes:
        r, s = decode_dss_signature(self.signature)
        rb = r.to_bytes(32, byteorder='big')
        sb = s.to_bytes(32, byteorder='big')
        return Transaction.FORMAT.pack(self.amount, self.payer,
                                       self.payee, rb, sb)

    @staticmethod
    def from_bytes(b: bytes):
        a, payer, payee, rb, sb = Transaction.FORMAT.unpack(b)
        r = int.from_bytes(rb, byteorder='big')
        s = int.from_bytes(sb, byteorder='big')
        return Transaction(amount=a, payer=payer, payee=payee,
                           signature=encode_dss_signature(r, s))


@dataclass()
class Wallet:
    public_key: ec.EllipticCurvePublicKey
    private_key: ec.EllipticCurvePrivateKeyWithSerialization

    def serialize_public(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)

    def to_address(self) -> bytes:
        return binascii.b2a_base64(self.serialize_public(), newline=False)

    def create_transaction(self, amount: int, payee: bytes) -> Transaction:
        txn = Transaction(amount=amount, payer=self.serialize_public(),
                          payee=payee)
        txn.signature = self.private_key.sign(txn.to_signature_data(),
                                              ec.ECDSA(SHA256()))
        return txn

    def save_to_disk(self):
        s = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PrivateFormat.PKCS8,
                                           encryption_algorithm=serialization.BestAvailableEncryption(
                                               PRIVATE_KEY_ENCRYPTION_PASSWORD)
                                           )
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
class Block:
    transactions: List[Transaction]
    nonce: int = 0
    parent_hash: bytes = b'\x00' * 32
    block_hash: bytes = b'\x00' * 32

    def to_hash_challenge(self) -> bytearray:
        b = bytearray(struct.pack('!Q32sL', self.nonce, self.parent_hash,
                                  len(self.transactions)))
        for t in self.transactions:
            b.extend(t.to_bytes())
        return b

    def solve_hash_challenge(self, difficulty: int = HASH_DIFFICULTY,
                             max_tries=None):
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
                b[0:8] = struct.pack('!Q', self.nonce)

    def to_bytes(self) -> bytes:
        b = self.to_hash_challenge()
        b.extend(self.block_hash)
        return bytes(b)

    @staticmethod
    def from_bytes(b: bytes):
        f = '!Q32sL'
        sz = struct.calcsize(f)
        nonce, parent_hash, txn_len = struct.unpack(f, b[:sz])
        transactions = []
        for i in range(txn_len):
            txn = Transaction.from_bytes(b[sz:sz + Transaction.FORMAT.size])
            sz += Transaction.FORMAT.size
            transactions.append(txn)
        block_hash = b[sz:sz + 32]
        return Block(transactions=transactions, nonce=nonce,
                     parent_hash=parent_hash, block_hash=block_hash)
