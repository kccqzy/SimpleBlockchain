import abc
import base64
import os
import os.path
import sqlite3
import struct
from collections import OrderedDict
from dataclasses import dataclass, astuple
from decimal import Decimal
from enum import Enum
from typing import *

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, Hash

__all__ = ['PRIVATE_KEY_ENCRYPTION_PASSWORD', 'PRIVATE_KEY_PATH', 'COIN', 'BLOCK_REWARD', 'ZERO_HASH',
           'MINIMUM_DIFFICULTY_LEVEL',
           'base58_encode', 'base58_decode', 'format_money', 'sha256', 'Serializable', 'TransactionInput',
           'TransactionOutput', 'Transaction',
           'Wallet', 'Block', 'BlockchainStorage', 'MessageType', 'Message']

PRIVATE_KEY_ENCRYPTION_PASSWORD = b'passworrrrd'
PRIVATE_KEY_PATH = './cctf2019_blockchain_wallet'
COIN = 1_0000_0000
BLOCK_REWARD = 10 * COIN
ZERO_HASH = b'\x00' * 32
MINIMUM_DIFFICULTY_LEVEL = 16

BASE58_CODE_STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(rb: bytes) -> str:
    b = rb.lstrip(b'\x00')
    x = int.from_bytes(b, byteorder='big')
    rv = []
    while x > 0:
        x, r = divmod(x, 58)
        rv.append(BASE58_CODE_STRING[r])
    return ('1' * (len(rb) - len(b))) + ''.join(rv)


def base58_decode(rs: str) -> bytes:
    s = rs.lstrip('1')
    b = 1
    p = 0
    c = list(s)
    c.reverse()
    for i in c:
        pos = BASE58_CODE_STRING.find(i)
        if pos < 0:
            raise ValueError("Not a base58 string")
        p += b * pos
        b *= 58
    length = (p.bit_length() + 7) // 8
    rv = p.to_bytes(length=length + len(rs) - len(s), byteorder='big')
    return rv


def format_money(amt: int) -> str:
    return "{:,.8f}".format(Decimal(amt) / COIN)


def sha256(*bs):
    digest = Hash(SHA256(), backend=default_backend())
    for b in bs:
        digest.update(b)
    return digest.finalize()


class Serializable(abc.ABC):
    @abc.abstractmethod
    def serialize(self, b: bytearray):
        pass

    @classmethod
    @abc.abstractmethod
    def deserialize(cls, b: memoryview) -> Tuple['Serializable', memoryview]:
        pass

    def serialize_into_bytes(self) -> bytes:
        b = bytearray()
        self.serialize(b)
        return bytes(b)

    @classmethod
    def deserialize_from_bytes(cls, b: bytes) -> 'Serializable':
        return cls.deserialize(memoryview(b))[0]


@dataclass()
class TransactionInput(Serializable):
    __slots__ = ('transaction_hash', 'output_index')
    transaction_hash: bytes
    output_index: int

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!32sB')

    def serialize(self, b: bytearray):
        b.extend(TransactionInput.FORMAT.pack(*astuple(self)))

    @classmethod
    def deserialize(cls, b: memoryview) -> Tuple['TransactionInput', memoryview]:
        return TransactionInput(*TransactionInput.FORMAT.unpack_from(b)), b[TransactionInput.FORMAT.size:]


@dataclass()
class TransactionOutput(Serializable):
    __slots__ = ('amount', 'recipient_hash')
    amount: int
    recipient_hash: bytes

    FORMAT: ClassVar[struct.Struct] = struct.Struct('!Q32s')

    def serialize(self, b: bytearray):
        b.extend(TransactionOutput.FORMAT.pack(*astuple(self)))

    @classmethod
    def deserialize(cls, b: memoryview) -> Tuple['TransactionOutput', memoryview]:
        return TransactionOutput(*TransactionOutput.FORMAT.unpack_from(b)), b[TransactionOutput.FORMAT.size:]


@dataclass()
class Transaction(Serializable):
    __slots__ = ('payer', 'inputs', 'outputs', 'signature', 'transaction_hash')
    payer: bytes
    inputs: List[TransactionInput]
    outputs: List[TransactionOutput]
    signature: bytes
    transaction_hash: bytes

    HEADER_FORMAT: ClassVar[struct.Struct] = struct.Struct('!88sBB')

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

    @classmethod
    def deserialize(cls, b: memoryview) -> Tuple['Transaction', memoryview]:
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
        if len(b) < 64:
            raise ValueError("Serialized form too short")
        rb, sb = b[:32], b[32:64]
        r = int.from_bytes(rb, byteorder='big')
        s = int.from_bytes(sb, byteorder='big')
        sig = encode_dss_signature(r, s)
        return Transaction(payer=payer, inputs=inputs, outputs=outputs, signature=sig,
                           transaction_hash=sha256(sig)), b[64:]


@dataclass()
class Wallet:
    public_serialized: bytes
    private_key: ec.EllipticCurvePrivateKey

    @staticmethod
    def serialize_public(public_key) -> bytes:
        return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def create_raw_transaction(self, inputs: List[TransactionInput], outputs: List[TransactionOutput]) -> Transaction:
        txn = Transaction(payer=self.public_serialized, inputs=inputs, outputs=outputs, signature=b'',
                          transaction_hash=b'')
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

    def solve_hash_challenge(self, difficulty: int, max_tries: Optional[int] = None) -> Tuple[bool, int, bytes]:
        b = self.to_hash_challenge()
        if max_tries is None:
            max_tries = 1 << 63
        while max_tries > 0:
            max_tries -= 1
            this_hash = sha256(b)
            this_hash_num = int.from_bytes(this_hash, byteorder='big')
            if this_hash_num >> (32 * 8 - difficulty) == 0:
                self.block_hash = this_hash
                return True, self.nonce, this_hash
            else:
                self.nonce += 1
                self.nonce %= 1 << 63
                struct.pack_into('!Q', b, 0, self.nonce)
        return False, self.nonce, ZERO_HASH

    def verify_difficulty(self, difficulty) -> bool:
        hash_num = int.from_bytes(self.block_hash, byteorder='big')
        return hash_num >> (32 * 8 - difficulty) == 0

    def verify_hash_challenge(self, difficulty: Optional[int] = None) -> bool:
        return ((self.verify_difficulty(difficulty or MINIMUM_DIFFICULTY_LEVEL))
                and constant_time.bytes_eq(self.block_hash, sha256(self.to_hash_challenge())))

    def serialize(self, b: bytearray):
        b.extend(self.to_hash_challenge())
        b.extend(self.block_hash)

    @classmethod
    def deserialize(cls, b: memoryview) -> Tuple['Block', memoryview]:
        nonce, parent_hash, transactions_len = Block.HEADER_FORMAT.unpack_from(b)
        b = b[Block.HEADER_FORMAT.size:]
        transactions = []
        for i in range(transactions_len):
            txn, b = Transaction.deserialize(b)
            transactions.append(txn)
        if len(b) < 32:
            raise ValueError("Serialized form too short")
        block_hash = bytes(b[:32])
        return Block(transactions=transactions, nonce=nonce, parent_hash=parent_hash, block_hash=block_hash), b[32:]

    @staticmethod
    def new_mine_block(wallet: Wallet) -> 'Block':
        return Block(transactions=[wallet.create_raw_transaction(inputs=[], outputs=[
            TransactionOutput(amount=BLOCK_REWARD, recipient_hash=sha256(wallet.public_serialized))])])


class BlockchainStorage:
    __slots__ = ('path', 'conn', 'default_wallet')

    def __init__(self, path: Optional[str] = None, default_wallet: Optional[Wallet] = None):
        self.default_wallet = default_wallet if default_wallet is not None else Wallet.load_from_disk()
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
                    discovered_at DATE NOT NULL DEFAULT (datetime('now')),
                    CHECK ( block_height >= 0 )
                )
            ''')
            self.conn.execute('CREATE INDEX IF NOT EXISTS block_parent ON blocks (parent_hash)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS block_height ON blocks (block_height)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS block_discovered_at ON blocks (discovered_at)')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_hash BLOB NOT NULL PRIMARY KEY,
                    payer BLOB NOT NULL,
                    payer_hash BLOB NOT NULL,
                    signature BLOB NOT NULL
                )
            ''')
            self.conn.execute('CREATE INDEX IF NOT EXISTS transaction_payer ON transactions (payer_hash)')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transaction_in_block (
                    transaction_hash BLOB NOT NULL REFERENCES transactions,
                    block_hash BLOB NOT NULL REFERENCES blocks ON DELETE CASCADE,
                    transaction_index INTEGER NOT NULL,
                    UNIQUE (transaction_hash, block_hash),
                    UNIQUE (block_hash, transaction_index),
                    CHECK ( transaction_index >= 0 AND transaction_index < 2000 )
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS transaction_outputs (
                    out_transaction_hash BLOB NOT NULL REFERENCES transactions (transaction_hash),
                    out_transaction_index INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    recipient_hash BLOB NOT NULL,
                    PRIMARY KEY (out_transaction_hash, out_transaction_index),
                    UNIQUE (out_transaction_hash, recipient_hash),
                    CHECK ( amount > 0 ),
                    CHECK ( out_transaction_index >= 0 AND out_transaction_index < 256 )
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
                    FOREIGN KEY(out_transaction_hash, out_transaction_index) REFERENCES transaction_outputs DEFERRABLE INITIALLY DEFERRED,
                    CHECK ( in_transaction_index >= 0 AND in_transaction_index < 256 )
                )
            ''')
            self.conn.execute(
                'CREATE INDEX IF NOT EXISTS input_referred ON transaction_inputs (out_transaction_hash, out_transaction_index)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS trustworthy_wallets ( payer_hash BLOB NOT NULL PRIMARY KEY )')
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
                CREATE VIEW IF NOT EXISTS ancestors AS
                WITH RECURSIVE
                ancestors AS (
                    SELECT block_hash, block_hash AS ancestor, 0 AS path_length FROM blocks
                    UNION ALL
                    SELECT ancestors.block_hash, blocks.parent_hash AS ancestor, 1 + path_length AS path_length
                    FROM ancestors JOIN blocks ON ancestor = blocks.block_hash
                    WHERE blocks.parent_hash IS NOT NULL
                )
                SELECT * FROM ancestors
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS actual_block_heights AS
                SELECT block_hash, count(*) - 1 AS height FROM ancestors GROUP BY block_hash
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS block_confirmations AS
                SELECT ancestor AS block_hash, count(*) AS confirmations FROM ancestors GROUP BY ancestor
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS longest_chain AS
                WITH RECURSIVE
                initial AS (SELECT * FROM blocks ORDER BY block_height DESC, discovered_at ASC LIMIT 1),
                chain AS (
                    SELECT block_hash, parent_hash, block_height, 1 AS confirmations FROM initial
                    UNION ALL
                    SELECT blocks.block_hash, blocks.parent_hash, blocks.block_height, 1 + confirmations
                        FROM blocks JOIN chain ON blocks.block_hash = chain.parent_hash
                )
                SELECT * FROM chain
            ''')
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS all_tentative_txns AS
                WITH lc_transaction_in_block AS (
                    SELECT transaction_in_block.* FROM transaction_in_block NATURAL JOIN longest_chain
                ),
                txns_not_on_longest AS (
                    SELECT transaction_hash, payer, signature FROM transactions NATURAL LEFT JOIN lc_transaction_in_block
                    WHERE block_hash IS NULL
                )
                SELECT * from txns_not_on_longest WHERE transaction_hash IN (SELECT in_transaction_hash FROM transaction_inputs)
            ''')
            # trust (a) confirmed ones; (b) ones made by trustworthy wallets that are not block rewards
            self.conn.execute('''
                CREATE VIEW IF NOT EXISTS utxo AS
                WITH tx_confirmations AS (
                    SELECT transaction_in_block.transaction_hash, longest_chain.confirmations
                    FROM transaction_in_block NATURAL JOIN longest_chain
                ),
                all_utxo AS (
                    SELECT transaction_outputs.*
                    FROM transaction_outputs NATURAL LEFT JOIN transaction_inputs
                    WHERE in_transaction_index IS NULL
                ),
                all_utxo_confirmations AS (
                    SELECT all_utxo.*, ifnull(tx_confirmations.confirmations, 0) AS confirmations
                    FROM all_utxo LEFT JOIN tx_confirmations ON all_utxo.out_transaction_hash = tx_confirmations.transaction_hash
                ),
                trustworthy_even_if_unconfirmed AS (
                    SELECT transaction_hash
                    FROM transactions
                    NATURAL JOIN trustworthy_wallets
                    JOIN transaction_inputs ON transactions.transaction_hash = transaction_inputs.in_transaction_hash
                )
                SELECT *
                FROM all_utxo_confirmations
                WHERE confirmations > 0 OR out_transaction_hash IN (SELECT transaction_hash FROM trustworthy_even_if_unconfirmed)
            ''')

    def __del__(self):
        self.conn.close()

    def recreate_db(self):
        self.conn.close()
        if self.path != ':memory:':
            for suffix in ['', '-shm', '-wal']:
                try:
                    os.unlink(self.path + suffix)
                except OSError:
                    pass
        new_self = BlockchainStorage(self.path)
        self.conn, new_self.conn = new_self.conn, self.conn

    def produce_stats(self) -> dict:
        (longest_chain_length,) = self.conn.execute(
            'SELECT 1 + ifnull((SELECT max(block_height) FROM blocks), -1)').fetchone()
        (pending_txn_count,) = self.conn.execute(
            'SELECT count(*) FROM all_tentative_txns').fetchone()
        return {
            '# of Blocks': str(longest_chain_length),
            '# of Pending Transactions': str(pending_txn_count),
        }

    def make_wallet_trustworthy(self, h: bytes):
        self.conn.execute('INSERT OR REPLACE INTO trustworthy_wallets VALUES (?)', (h,))

    def make_wallet(self):
        w = Wallet.new()
        self.make_wallet_trustworthy(sha256(w.public_serialized))
        return w

    def _insert_transaction_raw(self, t: Transaction):
        self.conn.execute('''
                    INSERT OR REPLACE INTO transactions (transaction_hash, payer, payer_hash, signature)
                    VALUES (?,?,?,?)
                ''', (t.transaction_hash, t.payer, sha256(t.payer), t.signature))
        self.conn.executemany('INSERT OR REPLACE INTO transaction_outputs VALUES (?,?,?,?)',
                              ((t.transaction_hash, index, *astuple(out)) for index, out in enumerate(t.outputs)))
        self.conn.executemany('INSERT OR REPLACE INTO transaction_inputs VALUES (?,?,?,?)',
                              ((t.transaction_hash, index, *astuple(inp)) for index, inp in enumerate(t.inputs)))

    def _ensure_block_consistent(self, block_hash: bytes):
        violations = self.conn.execute('''
                   WITH
                   my_ancestors AS (
                       SELECT ancestor AS block_hash FROM ancestors WHERE block_hash = ?
                   ),
                   my_transaction_in_block AS (
                       SELECT transaction_in_block.* FROM transaction_in_block NATURAL JOIN my_ancestors
                   ),
                   my_transaction_inputs AS (
                       SELECT transaction_inputs.*
                       FROM transaction_inputs JOIN my_transaction_in_block
                       ON transaction_inputs.in_transaction_hash = my_transaction_in_block.transaction_hash
                   ),
                   my_transaction_outputs AS (
                       SELECT transaction_outputs.*
                       FROM transaction_outputs JOIN my_transaction_in_block
                       ON transaction_outputs.out_transaction_hash = my_transaction_in_block.transaction_hash
                   ),
                   error_input_referring_to_nonexistent_outputs AS (
                       SELECT count(*) AS violations_count FROM my_transaction_inputs NATURAL LEFT JOIN my_transaction_outputs
                       WHERE my_transaction_outputs.amount IS NULL
                   ),
                   error_double_spent AS (
                       SELECT count(*) AS violations_count FROM (
                           SELECT count(*) AS spent_times
                           FROM my_transaction_outputs NATURAL JOIN my_transaction_inputs
                           GROUP BY out_transaction_hash, out_transaction_index
                           HAVING spent_times > 1
                       )
                   )
                   SELECT (SELECT violations_count FROM error_input_referring_to_nonexistent_outputs),
                          (SELECT violations_count FROM error_double_spent)
                ''', (block_hash,)).fetchone()
        if violations[0] > 0:
            raise ValueError("Transaction(s) in block are not consistent with those in ancestor blocks; "
                             "transaction inputs refer to nonexistent outputs (x%d)" % violations[0])
        if violations[1] > 0:
            raise ValueError("Transaction(s) in block are not consistent with those in ancestor blocks; "
                             "transaction inputs are refer to spent outputs (x%d)" % violations[1])

    def receive_block(self, block: Block):
        if not all(t.verify_signature() for t in block.transactions):
            raise ValueError("Every transaction in a block must be correctly signed")

        if len(block.transactions) == 0 or len(block.transactions[0].inputs) != 0 or len(
                block.transactions[0].outputs) != 1 or block.transactions[0].outputs[0].amount != BLOCK_REWARD:
            raise ValueError(
                "The first transaction in a block must have no inputs, and only one output of exactly the reward amount")

        if not all(1 <= len(t.outputs) <= 256 for t in block.transactions):
            raise ValueError("Every transaction must have at least one output and at most 256")

        if not all(1 <= len(t.inputs) <= 256 for t in block.transactions[1:]):
            raise ValueError("Every transaction except for the first must have at least one input and at most 256")

        if not block.verify_hash_challenge():
            raise ValueError("Block has incorrect hash")

        if len(block.transactions) > 2000:
            raise ValueError("A block may have at most 2000 transactions")

        if block.nonce.bit_length() > 63:
            raise ValueError("Block nonce must be within 63 bits")

        try:
            with self.conn:
                self.conn.execute('INSERT OR REPLACE INTO blocks (block_hash, parent_hash, nonce) VALUES (?,?,?)', (
                    block.block_hash,
                    block.parent_hash if block.parent_hash != ZERO_HASH else None,
                    block.nonce,
                ))
                for t in block.transactions:
                    self._insert_transaction_raw(t)
                for index, t in enumerate(block.transactions):
                    self.conn.execute('INSERT INTO transaction_in_block VALUES (?,?,?)',
                                      (t.transaction_hash, block.block_hash, index))
                if self.conn.execute(
                        'SELECT count(*) FROM unauthorized_spending NATURAL JOIN transaction_in_block WHERE block_hash = ?',
                        (block.block_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction(s) in block contain unauthorized spending")
                if self.conn.execute(
                        'SELECT count(*) FROM transaction_credit_debit NATURAL JOIN transaction_in_block WHERE block_hash = ? AND debited_amount > credited_amount',
                        (block.block_hash,)).fetchone()[0] > 0:
                    raise ValueError("Transaction(s) in block spend more than they have")
                self._ensure_block_consistent(block.block_hash)
                self.conn.execute('''
                    UPDATE blocks
                    SET block_height = (SELECT ifnull((SELECT 1 + block_height FROM blocks WHERE block_hash = ?), 0))
                    WHERE block_hash = ?
                ''', (block.parent_hash, block.block_hash))
        except sqlite3.IntegrityError as e:
            raise ValueError('Block contains transactions that do not abide by all rules: ' + e.args[0]) from e

    def receive_tentative_transaction(self, *ts: Transaction):
        if not all(t.verify_signature() for t in ts):
            raise ValueError("The tentative transaction is not correctly signed")

        if not all(1 <= len(t.outputs) <= 256 and 1 <= len(t.inputs) <= 256 for t in ts):
            raise ValueError("The tentative transaction must have at least one input and one output, and at most 256")

        try:
            with self.conn:
                for t in ts:
                    self._insert_transaction_raw(t)
                for t in ts:
                    if self.conn.execute('SELECT count(*) FROM unauthorized_spending WHERE transaction_hash = ?',
                                         (t.transaction_hash,)).fetchone()[0] > 0:
                        raise ValueError("Transaction contains unauthorized spending")
                    if self.conn.execute(
                            'SELECT count(*) FROM transaction_credit_debit WHERE transaction_hash = ? AND debited_amount > credited_amount',
                            (t.transaction_hash,)).fetchone()[0] > 0:
                        raise ValueError("Transaction spends more than they have")
        except sqlite3.IntegrityError as e:
            raise ValueError(
                "Cannot accept tentative transaction because it does not abide by all rules: " + e.args[0]) from e

    def find_available_spend(self, wallet_public_key_hash: bytes) -> Iterator[Tuple[bytes, int, int]]:
        i: Callable[[], Optional[Tuple[bytes, int, int]]] = self.conn.execute(
            'SELECT out_transaction_hash, out_transaction_index, amount FROM utxo WHERE recipient_hash = ?',
            (wallet_public_key_hash,)).fetchone
        return iter(i, None)

    def find_wallet_balance(self, wallet_public_key_hash: bytes, required_confirmations: Optional[int] = None) -> int:
        if required_confirmations is None:
            c = self.conn.execute('SELECT sum(amount) FROM utxo WHERE recipient_hash = ?', (wallet_public_key_hash,))
        else:
            c = self.conn.execute('SELECT sum(amount) FROM utxo WHERE recipient_hash = ? AND confirmations >= ?', (wallet_public_key_hash, required_confirmations))
        (r,) = c.fetchone()
        return r if r else 0

    def create_simple_transaction(self, wallet: Optional[Wallet], requested_amount: int,
                                  recipient_hash: bytes) -> Transaction:
        if wallet is None:
            wallet = self.default_wallet
            if wallet is None:
                raise ValueError("No wallet provided nor found on disk")
        with self.conn:
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
            t = wallet.create_raw_transaction(inputs=inputs, outputs=outputs)
            self.receive_tentative_transaction(t)
            return t

    def get_longest_chain(self) -> List[Tuple[bytes, int]]:
        return self.conn.execute('SELECT block_hash, block_height FROM longest_chain').fetchall()

    def _fill_transaction_in_out(self, t: Transaction) -> Transaction:
        t.inputs = [TransactionInput(h, i) for h, i in self.conn.execute(
            'SELECT out_transaction_hash, out_transaction_index FROM transaction_inputs WHERE in_transaction_hash = ? ORDER BY in_transaction_index',
            (t.transaction_hash,)).fetchall()]
        t.outputs = [TransactionOutput(a, r) for a, r in self.conn.execute(
            'SELECT amount, recipient_hash FROM transaction_outputs WHERE out_transaction_hash = ? ORDER BY out_transaction_index',
            (t.transaction_hash,)).fetchall()]
        return t

    def get_block_by_hash(self, block_hash: bytes) -> Block:
        r = self.conn.execute('SELECT nonce, parent_hash, block_hash FROM blocks WHERE block_hash = ?',
                              (block_hash,)).fetchone()
        if r is None:
            raise ValueError("no such block")
        nonce, parent_hash, block_hash = r
        txns = [self._fill_transaction_in_out(Transaction(p, [], [], s, h)) for h, p, s in self.conn.execute(
            'SELECT transaction_hash, payer, signature FROM transactions NATURAL JOIN transaction_in_block WHERE block_hash = ? ORDER BY transaction_index',
            (block_hash,))]
        return Block(txns, nonce, parent_hash if parent_hash is not None else ZERO_HASH, block_hash)

    def get_all_tentative_transactions(self) -> List[Transaction]:
        txns = [self._fill_transaction_in_out(Transaction(p, [], [], s, h)) for h, p, s in
                self.conn.execute('SELECT * FROM all_tentative_txns').fetchall()]
        return txns

    def get_mineable_tentative_transactions(self, limit: int = 100) -> List[Transaction]:
        self.conn.execute('BEGIN')
        n = 0
        rv: List[Transaction] = []
        try:
            self.conn.execute("""INSERT INTO blocks (block_hash, parent_hash, nonce)
                VALUES (x'deadface',
                        (SELECT block_hash FROM blocks ORDER BY block_height DESC, discovered_at ASC LIMIT 1),
                        0)""")
            self.conn.execute('''
                    UPDATE blocks
                    SET block_height = (SELECT height FROM actual_block_heights WHERE block_hash = x'deadface')
                    WHERE block_hash = x'deadface'
                ''')
            while n < limit:
                all_tx = self.conn.execute('SELECT * FROM all_tentative_txns LIMIT ?', (limit - n,)).fetchall()
                if not all_tx:
                    break
                for h, p, s in all_tx:
                    self.conn.execute('SAVEPOINT before_insert')
                    self.conn.execute(
                        "INSERT INTO transaction_in_block (transaction_hash, block_hash, transaction_index) VALUES (?, x'deadface', ?)",
                        (h, n,))
                    try:
                        self._ensure_block_consistent(b'\xde\xad\xfa\xce')
                    except ValueError:
                        self.conn.execute('ROLLBACK TO before_insert')
                    else:
                        n += 1
                        rv.append(self._fill_transaction_in_out(Transaction(p, [], [], s, h)))
                        self.conn.execute('RELEASE before_insert')
                    if n == limit:
                        break
            return rv
        finally:
            self.conn.execute('ROLLBACK')

    def get_ui_transaction_by_hash(self, transaction_hash: bytes) -> Optional[OrderedDict]:
        try:
            self.conn.row_factory = sqlite3.Row
            rv = OrderedDict()
            r = self.conn.execute('SELECT payer, signature FROM transactions WHERE transaction_hash = ?',
                                  (transaction_hash,)).fetchone()
            if r is None:
                return None
            t = self._fill_transaction_in_out(Transaction(r[0], [], [], r[1], transaction_hash))
            rv['Transaction Hash'] = base64.urlsafe_b64encode(transaction_hash).decode()
            rv['Originating Wallet'] = base64.urlsafe_b64encode(sha256(t.payer)).decode()
            for i, tx_output in enumerate(t.outputs):
                rv['Output %d Amount' % i] = format_money(tx_output.amount)
                rv['Output %d Recipient' % i] = base64.urlsafe_b64encode(tx_output.recipient_hash).decode()
            for i, tx_input in enumerate(t.inputs):
                rv['Input %d' % i] = '%s.%d' % (
                    base64.urlsafe_b64encode(tx_input.transaction_hash).decode(), tx_input.output_index)
            if not t.inputs:
                rv['Input'] = 'None (this is a miner reward)'
            r = self.conn.execute('SELECT * FROM transaction_credit_debit WHERE transaction_hash = ?',
                                  (transaction_hash,)).fetchone()
            if r is not None:
                rv['Credit Amount'] = format_money(r['credited_amount'])
                rv['Debit Amount'] = format_money(r['debited_amount'])
            r = self.conn.execute(
                'SELECT confirmations FROM block_confirmations WHERE block_hash IN (SELECT block_hash FROM transaction_in_block WHERE transaction_hash = ?)',
                (transaction_hash,)).fetchall()
            if not r:
                rv['Confirmations'] = 'none'
            else:
                rv['Confirmations'] = ', '.join(str(c[0]) for c in r)
            return rv
        finally:
            self.conn.row_factory = None

    def prepare_mineable_block(self, miner_wallet: Optional[Wallet]) -> Block:
        if miner_wallet is None:
            miner_wallet = self.default_wallet
            if miner_wallet is None:
                raise ValueError("No wallet provided nor found on disk")
        block = Block.new_mine_block(miner_wallet)
        block.transactions.extend(self.get_mineable_tentative_transactions())
        r = self.conn.execute(
            'SELECT block_hash FROM blocks ORDER BY block_height DESC, discovered_at ASC LIMIT 1').fetchone()
        if r is not None:
            block.parent_hash = r[0]
        return block

    def integrity_check(self):
        (r,) = self.conn.execute('PRAGMA integrity_check').fetchone()
        if r != 'ok':
            raise RuntimeError("Database corrupted")
        r = self.conn.execute('PRAGMA foreign_key_check').fetchone()
        if r is not None:
            raise RuntimeError("Database corrupted: contains invalid foreign key references")
        (r,) = self.conn.execute('SELECT count(*) FROM unauthorized_spending').fetchone()
        if r > 0:
            raise RuntimeError("Database corrupted: contains %d instance(s) of unauthorized spending" % r)
        (r,) = self.conn.execute(
            'SELECT count(*) FROM transaction_credit_debit WHERE debited_amount > credited_amount').fetchone()
        if r > 0:
            raise RuntimeError("Database corrupted: contains %d instance(s) of overspent transactions" % r)
        (r,) = self.conn.execute(
            'select count(*) from blocks NATURAL left join actual_block_heights where block_height is not height').fetchone()
        if r > 0:
            raise RuntimeError("Database corrupted: contains %d instance(s) of incorrect block_height" % r)
        leaf_blocks = self.conn.execute(
            'SELECT b1.block_hash FROM blocks AS b1 LEFT JOIN blocks AS b2 ON b1.block_hash = b2.parent_hash WHERE b2.parent_hash IS NULL').fetchall()
        for b, in leaf_blocks:
            try:
                self._ensure_block_consistent(b)
            except ValueError as e:
                raise RuntimeError("Database corrupted: block %r is not consistent: %s" % (b, e.args[0])) from e


class MessageType(Enum):
    GetCurrentDifficultyLevel = 1
    ReplyDifficultyLevel = 2  # arg: int
    GetLongestChain = 3
    ReplyLongestChain = 4  # arg: List[Tuple[bytes, int]]
    GetBlockByHash = 5  # arg: bytes
    ReplyBlockByHash = 6  # arg: Block
    GetTentativeTransactions = 7
    ReplyTentativeTransactions = 8  # arg: List[Transaction]
    AnnounceNewMinedBlock = 9  # arg: Block
    AnnounceNewTentativeTransaction = 10  # arg: Transaction


class Message(Serializable):
    message_type: MessageType
    arg: Optional[Any]

    def __init__(self, message_type: MessageType, arg: Optional[Any] = None):
        self.message_type = message_type
        self.arg = arg

    def __repr__(self):
        return "Message(%s%s)" % (self.message_type, ', ' + repr(self.arg) if self.arg is not None else '')

    def serialize(self, b: bytearray):
        b.extend(struct.pack('B', self.message_type.value))
        if self.message_type is MessageType.ReplyDifficultyLevel:
            b.extend(struct.pack('B', self.arg))
        elif self.message_type is MessageType.ReplyLongestChain:
            chain = cast(List[Tuple[bytes, int]], self.arg)
            b.extend(struct.pack('!L', len(chain)))
            for h, i in chain:
                b.extend(h)
                b.extend(struct.pack('!L', i))
        elif self.message_type is MessageType.GetBlockByHash:
            b.extend(self.arg)
        elif self.message_type is MessageType.ReplyBlockByHash:
            cast(Block, self.arg).serialize(b)
        elif self.message_type is MessageType.ReplyTentativeTransactions:
            txns = cast(List[Transaction], self.arg)
            b.extend(struct.pack('!H', len(txns)))
            for t in txns:
                t.serialize(b)
        elif self.message_type is MessageType.AnnounceNewMinedBlock:
            cast(Block, self.arg).serialize(b)
        elif self.message_type is MessageType.AnnounceNewTentativeTransaction:
            cast(Transaction, self.arg).serialize(b)

    @classmethod
    def deserialize(cls, b: memoryview) -> Tuple['Message', memoryview]:
        (kind,) = struct.unpack_from('B', b)
        b = b[1:]
        kind = MessageType(kind)
        if kind is MessageType.ReplyDifficultyLevel:
            (level,) = struct.unpack_from('B', b)
            return Message(kind, level), b[1:]
        elif kind is MessageType.ReplyLongestChain:
            (chain_length,) = struct.unpack_from('!L', b)
            b = b[4:]
            chain = []
            for i in range(chain_length):
                if len(b) < 32:
                    raise ValueError("Serialized form too short")
                h = b[:32]
                b = b[32:]
                (i,) = struct.unpack_from('!L', b)
                b = b[4:]
                chain.append((bytes(h), i))
            return Message(kind, chain), b
        elif kind is MessageType.GetBlockByHash:
            if len(b) < 32:
                raise ValueError("Serialized form too short")
            return Message(kind, bytes(b[:32])), b[32:]
        elif kind is MessageType.ReplyBlockByHash:
            block, b = Block.deserialize(b)
            return Message(kind, block), b
        elif kind is MessageType.ReplyTentativeTransactions:
            (txn_len,) = struct.unpack_from('!H', b)
            b = b[2:]
            txns = []
            for i in range(txn_len):
                txn, b = Transaction.deserialize(b)
                txns.append(txn)
            return Message(kind, txns), b
        elif kind is MessageType.AnnounceNewMinedBlock:
            block, b = Block.deserialize(b)
            return Message(kind, block), b
        elif kind is MessageType.AnnounceNewTentativeTransaction:
            txn, b = Transaction.deserialize(b)
            return Message(kind, txn), b
        else:
            return Message(kind), b
