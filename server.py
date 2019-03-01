import random
import asyncio
import concurrent.futures
import logging
import os
import struct
import sys
from typing import *

import aiohttp
from aiohttp import web

from blockchain import BlockchainStorage, MessageType, Message, Wallet, Block, Transaction, TransactionOutput, \
    TransactionInput, BLOCK_REWARD, sha256

CURRENT_DIFFICULTY_LEVEL = int(os.getenv('CURRENT_DIFFICULTY_LEVEL', '20'))

routes = web.RouteTableDef()

DATABASE_PATH = os.getenv('DATABASE_PATH', './bs-server.db')
BLOCKCHAIN = None


def call_with_global_blockchain(method, *args, **kwargs):
    return method(BLOCKCHAIN, *args, **kwargs)


def initialize_worker(_x):
    global BLOCKCHAIN
    os.setpgid(0, 0)  # Prevent receiving SIGINT inside worker
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    BLOCKCHAIN = BlockchainStorage(DATABASE_PATH)


pool = concurrent.futures.ProcessPoolExecutor(initializer=initialize_worker, initargs=[0])  # TODO not global


@routes.get('/')
async def index(_req):
    return web.HTTPMovedPermanently('/ui/index.html')


@routes.get('/ws')
async def begin_network(req: web.Request):
    loop = asyncio.get_event_loop()
    ws = web.WebSocketResponse()
    await ws.prepare(req)

    async def send(message: Message):
        await ws.send_bytes(message.serialize_into_bytes())

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
        if m.message_type is MessageType.GetCurrentDifficultyLevel:
            await send(Message(MessageType.ReplyDifficultyLevel, CURRENT_DIFFICULTY_LEVEL))
        elif m.message_type is MessageType.GetLongestChain:
            longest_chain = await loop.run_in_executor(pool, call_with_global_blockchain,
                                                       BlockchainStorage.get_longest_chain)
            await send(Message(MessageType.ReplyLongestChain, longest_chain))
        elif m.message_type is MessageType.GetBlockByHash:
            try:
                block = await loop.run_in_executor(pool, call_with_global_blockchain,
                                                   BlockchainStorage.get_block_by_hash, m.arg)
            except ValueError:
                print("WARNING: client requested non-existent block: %r" % m.arg)
            else:
                await send(Message(MessageType.ReplyBlockByHash, block))
        elif m.message_type is MessageType.GetTentativeTransactions:
            txns = await loop.run_in_executor(pool, call_with_global_blockchain,
                                              BlockchainStorage.get_all_tentative_transactions)
            await send(Message(MessageType.ReplyTentativeTransactions, txns))
        elif m.message_type is MessageType.AnnounceNewTentativeTransaction:
            # TODO send to everyone as well
            print("Received tentative txn", m.arg)
        elif m.message_type is MessageType.AnnounceNewMinedBlock:
            raise NotImplementedError

    return ws


def create_genesis(bs: BlockchainStorage) -> List[Wallet]:
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
    bs.receive_block(genesis_block)
    return wallets


def make_random_transactions(bs: BlockchainStorage, count: int, wallets: List[Wallet]) -> None:
    for i in range(count):
        sender, recipient = random.sample(wallets, k=2)
        amount = random.randrange(bs.find_wallet_balance(sha256(sender.public_serialized)) // 100)
        t = bs.create_simple_transaction(sender, amount,
                                         sha256(recipient.public_serialized))
        bs.receive_tentative_transaction(t)


def main():
    print("Initializing blank blockchain...", file=sys.stderr)
    bs = BlockchainStorage(DATABASE_PATH)
    bs.recreate_db()
    wallets = create_genesis(bs)
    make_random_transactions(bs, 100, wallets)
    for i in range(5):
        print("Preparing block %d..." % (i + 1), file=sys.stderr)
        block = bs.prepare_mineable_block(wallets[0])
        block.nonce = int.from_bytes(os.urandom(8), byteorder='big')
        print("Mining block %d..." % (i + 1), file=sys.stderr)
        block.solve_hash_challenge(16)
        bs.receive_block(block)
        make_random_transactions(bs, 100, wallets)
    del bs  # Once the app starts, do not allow access to the database, except through the workers

    logger = logging.getLogger('aiohttp.access')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

    app = web.Application()
    app.add_routes(routes)
    app.add_routes([web.static('/ui', './ui', follow_symlinks=True)])
    web.run_app(app)


if __name__ == "__main__":
    main()
