import copy
import asyncio
import base64
import binascii
import concurrent.futures
import decimal
import itertools
import os
import readline
import shlex
import signal
import struct
import sys
from contextlib import AsyncExitStack
from decimal import Decimal
from enum import Enum
from typing import *

import aiohttp

from blockchain import BlockchainStorage, Wallet, PRIVATE_KEY_PATH, MINIMUM_DIFFICULTY_LEVEL, MessageType, Message, \
    Transaction, Block, BANNER, ZERO_HASH, COIN, format_money

SERVER_URI = os.getenv('SERVER_URI', 'http://localhost:8080/ws')
DATABASE_PATH = os.getenv('DATABASE_PATH', './bs-client.db')  # TODO find another place to store it
MINING_WORKERS = max(1, int(os.getenv('MINING_WORKERS', os.cpu_count() - 1)))
MAX_HASH_BYTES_PER_CHUNK = 80000000
BLOCKCHAIN = None

HELP = '''Welcome to the CoinTF Blockchain client.

You can use the following commands interactively:

    status
        View status of the client and nerdy statistics about the current
        blockchain, such as the number of transactions, the number of blocks,
        etc.

    balance <wallet>
        View the amount of money <wallet> has. This includes transactions that
        have been submitted to the CoinTF network and received by this client
        but not yet included in any blocks, as well as transactions that have
        not yet received sufficient number of confirmations.

    pay <wallet> <amount>
        Pay <wallet> a certain amount of money. You need to have this amount of
        money in your wallet in order to create the transaction.

    viewtransaction <txn-hash>
        View details of a transaction identified by its hash. You can provide
        the hash in either base64 or hex. Information displayed includes its
        initiator, its inputs and outputs, debited and credited amounts, and
        the number of confirmations.

    viewblock <block-hash>
        View details of a block identified by its hash. You can provide the
        hash in either base64 or hex. Information displayed includes the number
        of transactions in this block, the miner, etc.

    longest
        View the current longest chain on the network.

    help
        Display this message.
'''


def call_with_global_blockchain(method, *args, **kwargs):
    if BLOCKCHAIN is None:
        raise ValueError("Blockchain is not properly initialized; are you a worker?")
    return method(BLOCKCHAIN, *args, **kwargs)


def initialize_worker(_x):
    global BLOCKCHAIN
    os.setpgid(0, 0)  # Prevent receiving SIGINT inside worker
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)
    BLOCKCHAIN = BlockchainStorage(DATABASE_PATH)


class UserInput(Enum):
    Balance = "balance"
    Pay = "pay"
    Status = "status"
    ViewTxn = "viewtransaction"
    ViewLongestChain = "longest"
    ViewBlock = "viewblock"


class BlockchainClient(AsyncExitStack):
    __slots__ = ('loop', 'is_ready', 'queued_new_blocks', 'queued_txns', 'difficulty_level', 'mining_task', 'db_exec',
                 'mining_exec', 'readline_exec', 'ws')

    def __init__(self):
        super().__init__()
        self.loop = asyncio.get_event_loop()
        self.is_ready = False
        self.queued_new_blocks = []
        self.queued_txns = []
        self.difficulty_level = MINIMUM_DIFFICULTY_LEVEL
        self.mining_task = None

    async def __aenter__(self):
        await super().__aenter__()
        self.db_exec = self.enter_context(
            concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0], max_workers=3))
        self.mining_exec = self.enter_context(
            concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0],
                                                   max_workers=MINING_WORKERS))
        self.readline_exec = self.enter_context(concurrent.futures.ThreadPoolExecutor(max_workers=1))
        session = await self.enter_async_context(aiohttp.ClientSession())
        self.ws = await self.enter_async_context(session.ws_connect(SERVER_URI, heartbeat=30, max_msg_size=0))
        return self

    async def send(self, ty: MessageType, arg=None) -> None:
        message = Message(ty, arg)
        await self.ws.send_bytes(message.serialize_into_bytes())

    @staticmethod
    def expect(message: Message, ty: MessageType) -> Message:
        if message.message_type is not ty:
            raise ValueError("Unexpected message type from server:", message.message_type)
        return message

    async def run_db(self, method, *args):
        return await self.loop.run_in_executor(self.db_exec, call_with_global_blockchain, method, *args)

    async def did_receive_block(self, b: Block) -> None:
        try:
            await self.run_db(BlockchainStorage.receive_block, b)
        except ValueError:
            pass

    async def did_receive_transaction(self, t: Transaction) -> None:
        try:
            await self.run_db(BlockchainStorage.receive_tentative_transaction, t)
        except ValueError:
            pass

    async def resync(self) -> AsyncGenerator[None, Message]:
        self.is_ready = False
        await self.send(MessageType.GetCurrentDifficultyLevel)
        received = self.expect((yield), MessageType.ReplyDifficultyLevel)
        self.difficulty_level = received.arg

        await self.send(MessageType.GetLongestChain)
        received = self.expect((yield), MessageType.ReplyLongestChain)
        their_longest_chain = cast(List[Tuple[bytes, int]], received.arg)
        their_longest_chain.sort(key=lambda k: k[1])
        our_longest_chain = await self.run_db(BlockchainStorage.get_longest_chain)
        our_longest_chain.sort(key=lambda x: x[1])
        for theirs, ours in itertools.zip_longest(their_longest_chain, our_longest_chain):
            if theirs == ours:
                continue
            elif theirs is None:
                break
            else:
                await self.send(MessageType.GetBlockByHash, theirs[0])
                received = self.expect((yield), MessageType.ReplyBlockByHash)
                await self.did_receive_block(received.arg)

        await self.send(MessageType.GetTentativeTransactions)
        received = self.expect((yield), MessageType.ReplyTentativeTransactions)
        for t in received.arg:
            t = cast(Transaction, t)
            await self.did_receive_transaction(t)

        blocks, self.queued_new_blocks = self.queued_new_blocks, []
        txns, self.queued_txns = self.queued_txns, []
        for b in blocks:
            await self.did_receive_block(b)
        for t in txns:
            await self.did_receive_transaction(t)
        self.is_ready = True

    @staticmethod
    def decode_intelligent(s: str, expected_length: int = 32) -> Optional[bytes]:
        try:
            r = base64.urlsafe_b64decode(s)
        except (binascii.Error, ValueError):
            pass
        else:
            if len(r) == expected_length:
                return r
        try:
            r = binascii.a2b_hex(s)
        except (binascii.Error, ValueError):
            pass
        else:
            if len(r) == expected_length:
                return r

    @staticmethod
    def print_aligned(d: Mapping[str, str]) -> None:
        longest_key_length = max(len(k) + 1 for k in d.keys())
        fmt_str = '%%-%ds %%s' % longest_key_length
        for k, v in d.items():
            print(fmt_str % (k + ':', v))

    @staticmethod
    def parse_user_input(cmd: str):
        cmd_split = shlex.split(cmd.strip(), comments=True)
        if not cmd_split:
            return
        elif cmd_split[0] == 'help':
            print(HELP)
            return
        elif cmd_split[0] == 'exit':
            print("To exit, type Control-D.")
            return
        elif cmd_split[0] == 'quit':
            print("To quit, type Control-D.")
            return
        elif cmd_split[0] == UserInput.Balance.value:
            if len(cmd_split) < 2:
                print('Wrong number of arguments')
                return
            yield UserInput.Balance
            for addr in cmd_split[1:]:
                b = BlockchainClient.decode_intelligent(addr)
                if b is None:
                    print("Unrecognized address %r" % addr)
                    continue
                yield b
        elif cmd_split[0] == UserInput.Pay.value:
            if len(cmd_split) != 3:
                print('Wrong number of arguments')
                return
            addr, amount = cmd_split[1:]
            recipient_hash = BlockchainClient.decode_intelligent(addr)
            if recipient_hash is None:
                print('Incorrect address')
                return
            try:
                amount = int((Decimal(amount) * COIN).to_integral())
                assert amount > 0
            except (decimal.InvalidOperation, AssertionError):
                print('Invalid amount')
                return
            yield UserInput.Pay
            yield (amount, recipient_hash)
        elif cmd_split[0] == UserInput.Status.value:
            yield UserInput.Status
        elif cmd_split[0] == UserInput.ViewTxn.value:
            if len(cmd_split) < 2:
                print('Wrong number of arguments')
                return
            yield UserInput.ViewTxn
            for i, arg in enumerate(cmd_split[1:]):
                txn_hash = BlockchainClient.decode_intelligent(arg)
                if txn_hash is None:
                    print("Incorrect transaction hash %r" % arg)
                    continue
                yield txn_hash
        elif cmd_split[0] == UserInput.ViewLongestChain.value:
            yield UserInput.ViewLongestChain
        elif cmd_split[0] == UserInput.ViewBlock.value:
            if len(cmd_split) < 2:
                print('Wrong number of arguments')
                return
            yield UserInput.ViewBlock
            for i, arg in enumerate(cmd_split[1:]):
                block_hash = BlockchainClient.decode_intelligent(arg)
                if block_hash is None:
                    print("Incorrect block hash %r" % arg)
                    continue
                yield block_hash
        else:
            print("Unrecognized command %r" % cmd_split[0])

    async def handle_user_interaction(self) -> None:
        while True:
            self.loop.add_signal_handler(signal.SIGINT, self.sigint_handler)
            # When reading a line, we unfortunately cannot correctly handle SIGINT.
            try:
                cmd = await self.loop.run_in_executor(self.readline_exec, input, '==> ')
            except (EOFError, KeyboardInterrupt):
                print("\nQuitting...")
                return
            finally:
                self.loop.remove_signal_handler(signal.SIGINT)
            g = BlockchainClient.parse_user_input(cmd)
            try:
                cmd_ty: UserInput = next(g)
            except StopIteration:
                continue
            if cmd_ty is UserInput.Balance:
                for b in g:
                    balance = await self.run_db(BlockchainStorage.find_wallet_balance, b)
                    print("Address %s has balance %s" % (
                        base64.urlsafe_b64encode(b).decode(), format_money(balance)))
            elif cmd_ty is UserInput.Pay:
                for amount, recipient_hash in g:
                    try:
                        await self.run_db(BlockchainStorage.create_simple_transaction, None, amount, recipient_hash)
                    except ValueError:
                        print('Insufficient balance')
                    else:
                        print('Transaction created')
            elif cmd_ty is UserInput.Status:
                stats: dict = await self.run_db(BlockchainStorage.produce_stats)
                stats['Current Difficulty Level'] = str(self.difficulty_level)
                stats['Synchronization'] = 'Done' if self.is_ready else 'In Progress'
                stats['Mining Task'] = 'Not Started' if self.mining_task is None else (
                    'Stopped' if self.mining_task.done() else 'Running'
                )
                stats['Connection'] = 'Closed' if self.ws.closed else 'Alive'
                BlockchainClient.print_aligned(stats)
            elif cmd_ty is UserInput.ViewTxn:
                for txn_hash in g:
                    rv = await self.run_db(BlockchainStorage.get_ui_transaction_by_hash, txn_hash)
                    if rv is None:
                        print("Transaction %s does not exist" % base64.urlsafe_b64encode(txn_hash).decode())
                    else:
                        BlockchainClient.print_aligned(rv)
            elif cmd_ty is UserInput.ViewLongestChain:
                chain = await self.run_db(BlockchainStorage.get_longest_chain)
                for block_hash, i in chain:
                    print('Height %d block %s' % (i, base64.urlsafe_b64encode(block_hash).decode()))
            elif cmd_ty is UserInput.ViewBlock:
                for block_hash in g:
                    try:
                        block: Block = await self.run_db(BlockchainStorage.get_block_by_hash, block_hash)
                    except ValueError:
                        print('Block %s does not exist' % base64.urlsafe_b64encode(block_hash).decode())
                        continue
                    print('Block %s' % base64.urlsafe_b64encode(block.block_hash).decode())
                    print('    Parent:       %s' % (base64.urlsafe_b64encode(
                        block.parent_hash).decode() if block.parent_hash != ZERO_HASH else 'None'))
                    print('    Nonce:        %d' % block.nonce)
                    print('    Transactions:')
                    for t in block.transactions:
                        print('                 ', base64.urlsafe_b64encode(t.transaction_hash).decode())

    async def do_mining(self):
        while True:
            block = await self.run_db(BlockchainStorage.prepare_mineable_block, None)
            bl = len(block.to_hash_challenge())
            iterations = max(5, MAX_HASH_BYTES_PER_CHUNK // bl)
            block.nonce = int.from_bytes(os.urandom(8), byteorder='big')
            while True:
                tasks = []
                for i in range(MINING_WORKERS):
                    this_block = copy.copy(block)
                    this_block.nonce += (1 << 63) // MINING_WORKERS
                    this_block.nonce %= 1 << 63
                    tasks.append(self.loop.run_in_executor(self.mining_exec, Block.solve_hash_challenge, this_block,
                                                           self.difficulty_level, iterations))
                done, _ = await asyncio.wait(tasks)
                try:
                    _, block.nonce, block.block_hash = next(t.result() for t in done if t.result()[0])
                except StopIteration:
                    block.nonce += iterations
                    block.nonce %= 1 << 63
                else:
                    break
            try:
                await self.run_db(BlockchainStorage.receive_block, block)
            except ValueError:
                pass  # why?
            await asyncio.sleep(1)  # Give CPU a rest
            # await self.send(MessageType.AnnounceNewMinedBlock, final_block)

    async def receive_loop(self) -> None:
        resyncing = self.resync()
        await resyncing.asend(None)
        async for msg in self.ws:
            msg = cast(aiohttp.WSMessage, msg)
            if msg.type != aiohttp.WSMsgType.BINARY:
                print("WARNING: received nonsense data: " + repr(msg.data), file=sys.stderr)
                continue
            try:
                m = Message.deserialize_from_bytes(msg.data)
            except (ValueError, struct.error):
                print("WARNING: received nonsense data: " + repr(msg.data), file=sys.stderr)
                continue

            if m.message_type is MessageType.AnnounceNewMinedBlock:
                if self.is_ready:
                    await self.did_receive_block(m.arg)
                else:
                    self.queued_new_blocks.append(m.arg)
            elif m.message_type is MessageType.AnnounceNewTentativeTransaction:
                if self.is_ready:
                    await self.did_receive_transaction(m.arg)
                else:
                    self.queued_txns.append(m.arg)
            elif not self.is_ready:
                try:
                    await resyncing.asend(m)
                except StopAsyncIteration:
                    self.mining_task = self.loop.create_task(self.do_mining())

    @staticmethod
    def sigint_handler():
        print("\r\nType Control-D to quit.\r\n==> ", end='', flush=True)  # XXX Assuming we're in readline()

    async def run_client(self) -> None:
        print(BANNER)
        print('Ready. Type "help" for help. Type Control-D to quit.')

        t = self.loop.create_task(self.receive_loop())
        await self.handle_user_interaction()
        t.cancel()
        if self.mining_task is not None:
            self.mining_task.cancel()
        await self.ws.close()


async def main():
    if not os.isatty(0) or not os.isatty(1):
        print("Please use a terminal to run this.", file=sys.stderr)
        sys.exit(1)

    readline.parse_and_bind('tab: complete')
    readline.set_completer(
        lambda text, state: ([x.value + ' ' for x in UserInput if x.value.startswith(text)] + [None])[state])

    print("[-] Preparing database...")
    bs = BlockchainStorage(DATABASE_PATH)  # Just to catch existing errors in the DB
    try:
        bs.integrity_check()
    except RuntimeError as e:
        print("WARNING: recreating database:", e.args[0], file=sys.stderr)
        bs.recreate_db()  # NOTE This deletes all of this user's pending transactions even if not broadcast
    del bs

    print("[-] Loading wallet...")
    if Wallet.load_from_disk() is None:
        print("No wallet found; a wallet will be created for you at " + PRIVATE_KEY_PATH, file=sys.stderr)
        Wallet.new()

    print("[-] Will use %d worker(s) for mining once synchronization is finished" % MINING_WORKERS)

    async with BlockchainClient() as bc:
        await bc.run_client()


if __name__ == "__main__":
    asyncio.run(main())
