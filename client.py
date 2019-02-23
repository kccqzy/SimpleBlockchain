import asyncio
import base64
import binascii
import concurrent.futures
import decimal
import itertools
import os
import readline
import shlex
import struct
import sys
from decimal import Decimal
from enum import Enum
from typing import *

import aiohttp

from blockchain import BlockchainStorage, Wallet, PRIVATE_KEY_PATH, MINIMUM_DIFFICULTY_LEVEL, MessageType, Message, \
    Transaction, Block, BANNER, ZERO_HASH

SERVER_URI = os.getenv('SERVER_URI', 'http://localhost:8080/ws')
DATABASE_PATH = os.getenv('DATABASE_PATH', './bs-client.db')  # TODO find another place to store it
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


def print_aligned(d: Mapping[str, str]):
    longest_key_length = max(len(k) + 1 for k in d.keys())
    fmt_str = '%%-%ds %%s' % longest_key_length
    for k, v in d.items():
        print(fmt_str % (k + ':', v))


class UserInput(Enum):
    Balance = "balance"
    Pay = "pay"
    Status = "status"
    ViewTxn = "viewtransaction"
    ViewLongestChain = "longest"
    ViewBlock = "viewblock"


def parse_user_input(cmd: str):
    cmd_split = shlex.split(cmd.strip(), comments=True)
    if not cmd_split:
        return
    elif cmd_split[0] == 'help':
        print(HELP)
        return
    elif cmd_split[0] == 'balance':
        if len(cmd_split) < 2:
            print('Wrong number of arguments')
            return
        yield UserInput.Balance
        for addr in cmd_split[1:]:
            b = decode_intelligent(addr)
            if b is None:
                print("Unrecognized address %r" % addr)
                continue
            yield b
    elif cmd_split[0] == 'pay':
        if len(cmd_split) != 3:
            print('Wrong number of arguments')
            return
        addr, amount = cmd_split[1:]
        recipient_hash = decode_intelligent(addr)
        if recipient_hash is None:
            print('Incorrect address')
            return
        try:
            amount = int((Decimal(amount) * 1_0000_0000).to_integral())
            assert amount > 0
        except (decimal.InvalidOperation, AssertionError):
            print('Invalid amount')
            return
        yield UserInput.Pay
        yield (amount, recipient_hash)
    elif cmd_split[0] == 'status':
        yield UserInput.Status
    elif cmd_split[0] == 'view-transaction':
        if len(cmd_split) < 2:
            print('Wrong number of arguments')
            return
        yield UserInput.ViewTxn
        for i, arg in enumerate(cmd_split[1:]):
            txn_hash = decode_intelligent(arg)
            if txn_hash is None:
                print("Incorrect transaction hash %r" % arg)
                continue
            yield txn_hash
    elif cmd_split[0] == 'longest-chain':
        yield UserInput.ViewLongestChain
    elif cmd_split[0] == 'view-block':
        if len(cmd_split) < 2:
            print('Wrong number of arguments')
            return
        yield UserInput.ViewBlock
        for i, arg in enumerate(cmd_split[1:]):
            block_hash = decode_intelligent(arg)
            if block_hash is None:
                print("Incorrect block hash %r" % arg)
                continue
            yield block_hash
    else:
        print("Unrecognized command %r" % cmd_split[0])


async def main():
    """The main function that connects to the blockchain network and handles
all message exchanges.
    """
    if not os.isatty(0) or not os.isatty(1):
        print("Please use a terminal to run this.", file=sys.stderr)
        sys.exit(1)

    readline.parse_and_bind('tab: complete')
    readline.set_completer(
        lambda text, state: ([x.value + ' ' for x in UserInput if x.value.startswith(text)] + [None])[state])

    print("[-] Preparing database...", file=sys.stderr)
    bs = BlockchainStorage(DATABASE_PATH)  # Just to catch existing errors in the DB
    try:
        bs.integrity_check()
    except RuntimeError:
        print("Database contains invalid records", file=sys.stderr)
        sys.exit(1)
    del bs

    print("[-] Loading wallet...", file=sys.stderr)
    wallet = Wallet.load_from_disk()
    if wallet is None:
        print("No wallet found; a wallet will be created for you at " + PRIVATE_KEY_PATH, file=sys.stderr)
        wallet = Wallet.new()

    loop = asyncio.get_event_loop()
    with concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0], max_workers=3) as db_exec, \
            concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0],
                                                   max_workers=max(1, os.cpu_count() - 1)) as mining_exec, \
            concurrent.futures.ThreadPoolExecutor(max_workers=1) as readline_exec:
        async with aiohttp.ClientSession() as session, session.ws_connect(SERVER_URI, heartbeat=30,
                                                                          max_msg_size=0) as ws:
            print(BANNER)
            print('Ready. Type "help" for help. Type Control-D to quit.')

            is_ready = False
            queued_new_blocks = []  # newly announced blocks received when we were not yet ready
            queued_txns = []  # newly announced tentative transactions when we were not yet ready
            difficulty_level = MINIMUM_DIFFICULTY_LEVEL

            async def send(ty: MessageType, arg=None) -> None:
                message = Message(ty, arg)
                await ws.send_bytes(message.serialize_into_bytes())

            def expect(message: Message, ty: MessageType) -> Message:
                if message.message_type is not ty:
                    raise ValueError("Unexpected message type from server:", message.message_type)
                return message

            async def did_receive_block(b: Block):
                try:
                    await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                               BlockchainStorage.receive_block,
                                               b)
                except ValueError:
                    pass

            async def did_receive_transaction(t: Transaction):
                try:
                    await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                               BlockchainStorage.receive_tentative_transaction, t)
                except ValueError:
                    pass

            async def resync() -> AsyncGenerator[None, Message]:
                nonlocal is_ready
                is_ready = False
                await send(MessageType.GetCurrentDifficultyLevel)
                received = expect((yield), MessageType.ReplyDifficultyLevel)
                nonlocal difficulty_level
                difficulty_level = received.arg

                await send(MessageType.GetLongestChain)
                received = expect((yield), MessageType.ReplyLongestChain)
                their_longest_chain = cast(List[Tuple[bytes, int]], received.arg)
                their_longest_chain.sort(key=lambda k: k[1])
                our_longest_chain = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                               BlockchainStorage.get_longest_chain)
                our_longest_chain.sort(key=lambda x: x[1])
                for theirs, ours in itertools.zip_longest(their_longest_chain, our_longest_chain):
                    if theirs == ours:
                        continue
                    elif theirs is None:
                        break
                    else:
                        await send(MessageType.GetBlockByHash, theirs[0])
                        received = expect((yield), MessageType.ReplyBlockByHash)
                        await did_receive_block(received.arg)

                await send(MessageType.GetTentativeTransactions)
                received = expect((yield), MessageType.ReplyTentativeTransactions)
                for t in received.arg:
                    t = cast(Transaction, t)
                    await did_receive_transaction(t)

                nonlocal queued_new_blocks
                blocks, queued_new_blocks = queued_new_blocks, []
                nonlocal queued_txns
                txns, queued_txns = queued_txns, []
                for b in blocks:
                    await did_receive_block(b)
                for t in queued_txns:
                    await did_receive_transaction(t)
                is_ready = True

            async def handle_user_interaction():
                while True:
                    try:
                        cmd = await loop.run_in_executor(readline_exec, input, '==> ')
                    except (EOFError, KeyboardInterrupt):
                        print("\nQuitting...")
                        break
                    g = parse_user_input(cmd)
                    try:
                        cmd_ty: UserInput = next(g)
                    except StopIteration:
                        continue
                    if cmd_ty is UserInput.Balance:
                        for b in g:
                            balance = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                                 BlockchainStorage.find_wallet_balance, b)
                            print("Address %s has balance %.8f" % (
                            base64.urlsafe_b64encode(b).decode(), Decimal(balance) / 1_0000_0000))
                    elif cmd_ty is UserInput.Pay:
                        for amount, recipient_hash in g:
                            try:
                                await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                           BlockchainStorage.create_simple_transaction,
                                                           None, amount, recipient_hash)
                            except ValueError:
                                print('Insufficient balance')
                            else:
                                print('Transaction created')
                    elif cmd_ty is UserInput.Status:
                        stats: dict = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                                 BlockchainStorage.produce_stats)
                        stats['Current Difficulty Level'] = str(difficulty_level)
                        print_aligned(stats)
                    elif cmd_ty is UserInput.ViewTxn:
                        for txn_hash in g:
                            rv = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                            BlockchainStorage.get_ui_transaction_by_hash, txn_hash)
                            if rv is None:
                                print("Transaction %s does not exist" % base64.urlsafe_b64encode(txn_hash).decode())
                            else:
                                print_aligned(rv)
                    elif cmd_ty is UserInput.ViewLongestChain:
                        chain = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                           BlockchainStorage.get_longest_chain)
                        for block_hash, i in chain:
                            print('Height %d block %s' % (i, base64.urlsafe_b64encode(block_hash).decode()))
                    elif cmd_ty is UserInput.ViewBlock:
                        for block_hash in g:
                            try:
                                block: Block = await loop.run_in_executor(db_exec, call_with_global_blockchain,
                                                                          BlockchainStorage.get_block_by_hash,
                                                                          block_hash)
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

            async def do_mining():
                raise NotImplementedError

            async def receive_loop():
                resyncing = resync()
                await resyncing.asend(None)
                async for msg in ws:
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
                        if is_ready:
                            await did_receive_block(m.arg)
                        else:
                            queued_new_blocks.append(m.arg)
                    elif m.message_type is MessageType.AnnounceNewTentativeTransaction:
                        if is_ready:
                            await did_receive_transaction(m.arg)
                        else:
                            queued_txns.append(m.arg)
                    elif not is_ready:
                        try:
                            await resyncing.asend(m)
                        except StopAsyncIteration:
                            pass  # TODO start mining

            t = loop.create_task(receive_loop())
            await handle_user_interaction()
            t.cancel()
            await asyncio.sleep(0.3)
            await ws.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
