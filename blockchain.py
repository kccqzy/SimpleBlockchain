import abc
import os
import os.path
import random
import sqlite3
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
BLOCK_REWARD = 10_0000_0000
ZERO_HASH = b'\x00' * 32
MINIMUM_DIFFICULTY_LEVEL = 16


def sha256(*bs):
    digest = Hash(SHA256(), backend=default_backend())
    for b in bs:
        digest.update(b)
    return digest.finalize()


class Serializable(abc.ABC):
    @abc.abstractmethod
    def serialize(self, b: bytearray):
        pass

    @staticmethod
    @abc.abstractmethod
    def deserialize(b: memoryview) -> Tuple['Serializable', memoryview]:
        pass


@dataclass()
class TransactionInput(Serializable):
    transaction_hash: bytes
    output_index: int

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!32sH')

    def serialize(self, b: bytearray):
        b.extend(TransactionInput.FORMAT.pack(*astuple(self)))

    @staticmethod
    def deserialize(b: memoryview) -> Tuple['TransactionInput', memoryview]:
        return TransactionInput(*TransactionInput.FORMAT.unpack_from(b)), b[TransactionInput.FORMAT.size:]


@dataclass()
class TransactionOutput(Serializable):
    amount: int
    recipient_hash: bytes

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q32s')

    def serialize(self, b: bytearray):
        b.extend(TransactionOutput.FORMAT.pack(*astuple(self)))

    @staticmethod
    def deserialize(b: memoryview) -> Tuple['TransactionOutput', memoryview]:
        return TransactionOutput(*TransactionOutput.FORMAT.unpack_from(b)), b[TransactionOutput.FORMAT.size:]


@dataclass()
class Transaction(Serializable):
    payer: bytes
    inputs: List[TransactionInput]
    outputs: List[TransactionOutput]
    signature: bytes = b''
    transaction_hash: bytes = b''

    HEADER_FORMAT: ClassVar[struct.Struct] = struct.Struct('!88sHH')

    def to_signature_data(self) -> bytearray:
        b = bytearray(
            Transaction.HEADER_FORMAT.pack(self.payer, len(self.inputs), len(self.outputs)))
        for txn_input in self.inputs:
            txn_input.serialize(b)
        for txn_output in self.outputs:
            txn_output.serialize(b)
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

    def serialize(self, b: bytearray):
        b.extend(self.to_signature_data())
        r, s = decode_dss_signature(self.signature)
        b.extend(r.to_bytes(32, byteorder='big'))
        b.extend(s.to_bytes(32, byteorder='big'))

    @staticmethod
    def deserialize(b: memoryview) -> Tuple['Transaction', memoryview]:
        payer, input_len, output_len = Transaction.HEADER_FORMAT.unpack_from(b, 0)
        b = b[Transaction.HEADER_FORMAT.size:]
        inputs = []
        outputs = []
        for i in range(input_len):
            txn_input, b = TransactionInput.deserialize(b)
            inputs.append(txn_input)
        for i in range(output_len):
            txn_output, b = TransactionOutput.deserialize(b)
            outputs.append(txn_output)
        rb, sb = b[:32], b[32:64]
        r = int.from_bytes(rb, byteorder='big')
        s = int.from_bytes(sb, byteorder='big')
        sig = encode_dss_signature(r, s)
        return Transaction(payer=payer, inputs=inputs, outputs=outputs, signature=sig, transaction_hash=sha256(sig)), b[64:]


@dataclass()
class Wallet:
    public_serialized: bytes
    private_key: ec.EllipticCurvePrivateKey

    @staticmethod
    def serialize_public(public_key) -> bytes:
        return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def create_raw_transaction(self, inputs: List[TransactionInput], outputs: List[TransactionOutput]) -> Transaction:
        txn = Transaction(payer=self.public_serialized, inputs=inputs, outputs=outputs)
        txn.signature = self.private_key.sign(txn.to_signature_data(),
                                              ec.ECDSA(SHA256()))
        txn.transaction_hash = sha256(txn.signature)
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
            return Wallet(public_serialized=Wallet.serialize_public(loaded.public_key()), private_key=loaded)

    @staticmethod
    def new():
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()
        public_serialized = Wallet.serialize_public(public_key)
        assert len(public_serialized) == 88
        w = Wallet(public_serialized, private_key)
        return w


@dataclass()
class Block(Serializable):
    transactions: List[Transaction]
    nonce: int = 0
    parent_hash: bytes = ZERO_HASH
    block_hash: bytes = ZERO_HASH

    HEADER_FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q32sL')

    def to_hash_challenge(self) -> bytearray:
        b = bytearray(Block.HEADER_FORMAT.pack(self.nonce, self.parent_hash, len(self.transactions)))
        for t in self.transactions:
            t.serialize(b)
        return b

    def solve_hash_challenge(self, difficulty: int, max_tries: Optional[int] = None):
        b = self.to_hash_challenge()
        if max_tries is None:
            max_tries = 1 << 64
        while max_tries > 0:
            max_tries -= 1
            this_hash = sha256(b)
            this_hash_num = int.from_bytes(this_hash, byteorder='big')
            if this_hash_num >> (32 * 8 - difficulty) == 0:
                self.block_hash = this_hash
                return
            else:
                self.nonce += 1
                self.nonce %= 1 << 64
                struct.pack_into('!Q', b, 0, self.nonce)

    def verify_hash_challenge(self, difficulty: Optional[int] = None):
        if difficulty is not None:
            hash_num = int.from_bytes(self.block_hash, byteorder='big')
            if hash_num >> (32 * 8 - difficulty) != 0:
                return False
        return self.block_hash == sha256(self.to_hash_challenge())

    def serialize(self, b: bytearray):
        b.extend(self.to_hash_challenge())
        b.extend(self.block_hash)

    @staticmethod
    def deserialize(b: memoryview) -> Tuple['Block', memoryview]:
        nonce, parent_hash, transactions_len = Block.HEADER_FORMAT.unpack_from(b)
        b = b[Block.HEADER_FORMAT.size:]
        transactions = []
        for i in range(transactions_len):
            txn, b = Transaction.deserialize(b)
            transactions.append(txn)
        block_hash = bytes(b[:32])
        return Block(transactions=transactions, nonce=nonce, parent_hash=parent_hash, block_hash=block_hash), b[32:]

    @staticmethod
    def new_mine_block(wallet: Wallet) -> 'Block':
        return Block(transactions=[wallet.create_raw_transaction(inputs=[], outputs=[
            TransactionOutput(amount=BLOCK_REWARD, recipient_hash=sha256(wallet.public_serialized))])])


class BlockchainStorage:
    def __init__(self, path: Optional[str] = None):
        self.path = path if path is not None else ':memory:'
        self.conn = sqlite3.connect(self.path)
        with self.conn:
            self.conn.execute('PRAGMA foreign_keys = ON')
            self.conn.execute('PRAGMA journal_mode = WAL')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    block_hash BLOB NOT NULL PRIMARY KEY,
                    parent_hash BLOB REFERENCES blocks (block_hash),
                    block_height INTEGER NOT NULL DEFAULT 0,
                    nonce INTEGER NOT NULL,
                    CHECK ( block_height >= 0 )
                )
            ''')
            self.conn.execute('CREATE INDEX IF NOT EXISTS block_parent ON blocks (parent_hash)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS block_height ON blocks (block_height)')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_hash BLOB NOT NULL PRIMARY KEY,
                    payer BLOB NOT NULL,
                    payer_hash BLOB NOT NULL,
                    signature BLOB NOT NULL
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transaction_in_block (
                    transaction_hash BLOB NOT NULL REFERENCES transactions,
                    block_hash BLOB NOT NULL REFERENCES blocks ON DELETE CASCADE,
                    transaction_index INTEGER NOT NULL,
                    UNIQUE (transaction_hash, block_hash),
                    UNIQUE (block_hash, transaction_index),
                    CHECK ( transaction_index >= 0 AND transaction_index < 65535 )
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transaction_outputs (
                    out_transaction_hash BLOB NOT NULL REFERENCES transactions (transaction_hash),
                    out_transaction_index INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    recipient_hash BLOB NOT NULL,
                    PRIMARY KEY (out_transaction_hash, out_transaction_index),
                    CHECK ( amount > 0 ),
                    CHECK ( out_transaction_index >= 0 AND out_transaction_index < 65535 )
                )
            ''')
            self.conn.execute('CREATE INDEX IF NOT EXISTS output_recipient ON transaction_outputs (recipient_hash)')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transaction_inputs (
                    in_transaction_hash BLOB NOT NULL REFERENCES transactions (transaction_hash),
                    in_transaction_index INTEGER NOT NULL,
                    out_transaction_hash BLOB NOT NULL,
                    out_transaction_index INTEGER NOT NULL,
                    PRIMARY KEY (in_transaction_hash, in_transaction_index),
                    UNIQUE (out_transaction_hash, out_transaction_index),
                    FOREIGN KEY(out_transaction_hash, out_transaction_index) REFERENCES transaction_outputs,
                    CHECK ( in_transaction_index >= 0 AND in_transaction_index < 65535 )
                )
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS transaction_full AS
                SELECT
                    transactions.transaction_hash,
                    transactions.payer,
                    transactions.signature,
                    out_transaction_index,
                    amount,
                    recipient_hash,
                    NULL AS in_transaction_index,
                    NULL AS referenced_th,
                    NULL AS referenced_output_index
                FROM transactions JOIN transaction_outputs ON transactions.transaction_hash = transaction_outputs.out_transaction_hash
                UNION ALL
                SELECT
                    transactions.transaction_hash,
                    transactions.payer,
                    transactions.signature,
                    NULL AS out_transaction_index,
                    NULL AS amount,
                    NULL AS recipient_hash,
                    in_transaction_index,
                    out_transaction_hash AS referenced_th,
                    out_transaction_index AS referenced_output_index
                FROM transactions LEFT JOIN transaction_inputs ON transactions.transaction_hash = transaction_inputs.in_transaction_hash
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS utxo AS
                SELECT transaction_outputs.*
                FROM transaction_outputs NATURAL LEFT JOIN transaction_inputs
                WHERE in_transaction_index IS NULL
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS unauthorized_spending AS
                SELECT transactions.*, transaction_outputs.recipient_hash AS owner_hash, transaction_outputs.amount
                FROM transactions
                JOIN transaction_inputs ON transactions.transaction_hash = transaction_inputs.in_transaction_hash
                NATURAL JOIN transaction_outputs
                WHERE payer_hash != owner_hash
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS transaction_credit_debit AS
                WITH
                transaction_debits AS (
                    SELECT out_transaction_hash AS transaction_hash, sum(amount) AS debited_amount
                    FROM transaction_outputs
                    GROUP BY transaction_hash
                ),
                transaction_credits AS (
                    SELECT in_transaction_hash AS transaction_hash, sum(transaction_outputs.amount) AS credited_amount
                    FROM transaction_inputs NATURAL JOIN transaction_outputs
                    GROUP BY transaction_hash
                )
                SELECT * FROM transaction_credits NATURAL JOIN transaction_debits NATURAL JOIN transactions
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS longest_chain AS
                WITH RECURSIVE
                initial AS (SELECT * FROM blocks ORDER BY block_height DESC LIMIT 1),
                chain AS (
                    SELECT block_hash, parent_hash, block_height FROM initial
                    UNION ALL
                    SELECT blocks.block_hash, blocks.parent_hash, blocks.block_height
                        FROM blocks JOIN chain ON blocks.block_hash = chain.parent_hash
                )
                SELECT * FROM chain
            ''')

    def __del__(self):
        self.conn.close()

    def _insert_transaction_raw(self, t: Transaction):
        self.conn.execute('''
                    INSERT OR REPLACE INTO transactions (transaction_hash, payer, payer_hash, signature)
                    VALUES (?,?,?,?)
                ''', (t.transaction_hash, t.payer, sha256(t.payer), t.signature))
        self.conn.executemany('INSERT OR REPLACE INTO transaction_outputs VALUES (?,?,?,?)',
                              ((t.transaction_hash, index, *astuple(out)) for index, out in enumerate(t.outputs)))
        self.conn.executemany('INSERT OR REPLACE INTO transaction_inputs VALUES (?,?,?,?)',
                              ((t.transaction_hash, index, *astuple(inp)) for index, inp in enumerate(t.inputs)))

    def receive_block(self, block: Block):
        if not all(t.verify_signature() for t in block.transactions):
            raise ValueError("Every transaction in a block must be correctly signed")

        if len(block.transactions) == 0 or len(block.transactions[0].inputs) != 0 or len(
                block.transactions[0].outputs) != 1 or block.transactions[0].outputs[0].amount != BLOCK_REWARD:
            raise ValueError(
                "The first transaction in a block must have no inputs, and only one output of exactly the reward amount")

        if not all(len(t.outputs) > 0 for t in block.transactions):
            raise ValueError("Every transaction must have at least one output")

        if not all(len(t.inputs) > 0 for t in block.transactions[1:]):
            raise ValueError("Every transaction except for the first in a block must have at least one input")

        if not block.verify_hash_challenge(difficulty=MINIMUM_DIFFICULTY_LEVEL):
            raise ValueError("Block has incorrect hash")

        with self.conn:
            try:
                self.conn.execute('INSERT OR REPLACE INTO blocks (block_hash, parent_hash, nonce) VALUES (?,?,?)', (
                    block.block_hash,
                    block.parent_hash if block.parent_hash != ZERO_HASH else None,
                    block.nonce,
                ))
                for t in block.transactions:
                    self._insert_transaction_raw(t)
                for index, t in enumerate(block.transactions):
                    self.conn.execute('INSERT INTO transaction_in_block VALUES (?,?,?)', (t.transaction_hash, block.block_hash, index))
                if self.conn.execute('SELECT count(*) FROM unauthorized_spending NATURAL JOIN transaction_in_block WHERE block_hash = ?',
                                     (block.block_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction(s) in block contain unauthorized spending")
                if self.conn.execute(
                        'SELECT count(*) FROM transaction_credit_debit NATURAL JOIN transaction_in_block WHERE block_hash = ? AND debited_amount > credited_amount',
                        (block.block_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction(s) in block spend more than they have")

                self.conn.execute('''
                    UPDATE blocks
                    SET block_height = (SELECT ifnull((SELECT 1 + block_height FROM blocks WHERE block_hash = ?), 0))
                    WHERE block_hash = ?
                ''', (block.parent_hash, block.block_hash))
            except sqlite3.IntegrityError as e:
                raise ValueError('Block contains transactions that do not abide by all rules') from e

    def receive_tentative_transaction(self, tentative_txn: Transaction):
        if not tentative_txn.verify_signature():
            raise ValueError("The tentative transaction is not correctly signed")

        if len(tentative_txn.outputs) == 0 or len(tentative_txn.inputs) == 0:
            raise ValueError("The tentative transaction must have at least one input and one output")

        with self.conn:
            try:
                self._insert_transaction_raw(tentative_txn)
                if self.conn.execute('SELECT count(*) FROM unauthorized_spending WHERE transaction_hash = ?',
                                     (tentative_txn.transaction_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction contains unauthorized spending")
                if self.conn.execute(
                        'SELECT count(*) FROM transaction_credit_debit WHERE transaction_hash = ? AND debited_amount > credited_amount',
                        (tentative_txn.transaction_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction spends more than they have")
            except sqlite3.IntegrityError as e:
                raise ValueError("Cannot accept tentative transaction because it does not abide by all rules") from e

    def find_available_spend(self, wallet_public_key_hash: bytes) -> Iterator[Tuple[bytes, int, int]]:
        cur = self.conn.execute(
            'SELECT out_transaction_hash, out_transaction_index, amount FROM utxo WHERE recipient_hash = ?',
            (wallet_public_key_hash,))
        while True:
            r = cur.fetchone()
            if r is None:
                break
            else:
                yield r

    def find_wallet_balance(self, wallet_public_key_hash: bytes):
        (r,) = self.conn.execute('SELECT sum(amount) FROM utxo WHERE recipient_hash = ?', (wallet_public_key_hash,)).fetchone()
        return r if r else 0

    def create_simple_transaction(self, wallet: Wallet, requested_amount: int, recipient_hash: bytes) -> Transaction:
        inputs = []
        amount_sum = 0
        for tx_hash, tx_out_i, amount in self.find_available_spend(sha256(wallet.public_serialized)):
            amount_sum += amount
            inputs.append(TransactionInput(transaction_hash=tx_hash, output_index=tx_out_i))
            if amount_sum >= requested_amount:
                break
        else:
            raise ValueError('Insufficient balance: wants %d but has %d' % (requested_amount, amount_sum))
        outputs = [TransactionOutput(amount=requested_amount, recipient_hash=recipient_hash)]
        if amount_sum > requested_amount:
            outputs.append(TransactionOutput(amount=amount_sum - requested_amount,
                                             recipient_hash=sha256(wallet.public_serialized)))
        return wallet.create_raw_transaction(inputs=inputs, outputs=outputs)

    def get_longest_chain(self) -> List[Tuple[bytes, int]]:
        return self.conn.execute('SELECT block_hash, block_height FROM longest_chain').fetchall()

    def _fill_transaction_in_out(self, t: Transaction):
        t.inputs = [TransactionInput(h, i) for h, i in self.conn.execute(
            'SELECT out_transaction_hash, out_transaction_index FROM transaction_inputs WHERE in_transaction_hash = ? ORDER BY in_transaction_index',
            (t.transaction_hash,)).fetchall()]
        t.outputs = [TransactionOutput(a, r) for a, r in self.conn.execute(
            'SELECT amount, recipient_hash FROM transaction_outputs WHERE out_transaction_hash = ? ORDER BY out_transaction_index',
            (t.transaction_hash,)).fetchall()]

    def get_transaction_by_hash(self, transaction_hash: bytes) -> Transaction:
        r = self.conn.execute('SELECT transaction_hash, payer, signature FROM transactions WHERE transaction_hash = ?',
                              (transaction_hash,)).fetchone()
        if r is None:
            raise ValueError("no such transaction")
        transaction_hash, payer, signature = r
        t = Transaction(payer, [], [], signature, transaction_hash)
        self._fill_transaction_in_out(t)
        return t

    def get_block_by_hash(self, block_hash: bytes) -> Block:
        r = self.conn.execute('SELECT nonce, parent_hash, block_hash FROM blocks WHERE block_hash = ?',
                              (block_hash,)).fetchone()
        if r is None:
            raise ValueError("no such block")
        nonce, parent_hash, block_hash = r
        txns = [Transaction(p, [], [], s, h) for h, p, s in self.conn.execute(
            'SELECT transaction_hash, payer, signature FROM transactions NATURAL JOIN transaction_in_block WHERE block_hash = ? ORDER BY transaction_index',
            (block_hash,))]
        for t in txns:
            self._fill_transaction_in_out(t)
        return Block(txns, nonce, parent_hash, block_hash)

    def get_all_tentative_transactions(self) -> List[Transaction]:
        txns = [Transaction(p, [], [], s, h) for h, p, s in self.conn.execute(
            'SELECT transaction_hash, payer, signature FROM transactions NATURAL LEFT JOIN transaction_in_block WHERE block_hash IS NULL').fetchall()]
        for t in txns:
            self._fill_transaction_in_out(t)
        return txns

    def create_genesis(self) -> List[Wallet]:
        wallets = []
        for i in range(10):
            wallets.append(Wallet.new())
        genesis_block = Block.new_mine_block(wallets[0])
        genesis_block_reward_hash = genesis_block.transactions[0].transaction_hash
        genesis_block.transactions.append(wallets[0].create_raw_transaction(
            inputs=[TransactionInput(transaction_hash=genesis_block_reward_hash, output_index=0)],
            outputs=[TransactionOutput(amount=BLOCK_REWARD // 10,
                                       recipient_hash=sha256(wallets[j].public_serialized)) for j in range(10)]))
        genesis_block.solve_hash_challenge(difficulty=16)
        self.receive_block(genesis_block)
        return wallets

    def make_random_transactions(self, count: int, wallets: List[Wallet]) -> None:
        for i in range(count):
            sender, recipient = random.sample(wallets, k=2)
            amount = random.randrange(self.find_wallet_balance(sha256(sender.public_serialized)) // 100)
            t = self.create_simple_transaction(sender, amount,
                                               sha256(recipient.public_serialized))
            self.receive_tentative_transaction(t)

    def prepare_mineable_block(self, miner_wallet: Wallet) -> Block:
        block = Block.new_mine_block(miner_wallet)
        block.transactions.extend(self.get_all_tentative_transactions())
        r = self.conn.execute('SELECT block_hash FROM blocks ORDER BY block_height DESC LIMIT 1').fetchone()
        if r is not None:
            block.parent_hash = r[0]
        return block
