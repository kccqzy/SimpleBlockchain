import asyncio
import concurrent.futures
import logging
import os
import struct
import sys
from typing import *

import aiohttp
from aiohttp import web

from blockchain import BlockchainStorage, MessageType, Message

CURRENT_DIFFICULTY_LEVEL = 17

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


def main():
    try:
        os.unlink(DATABASE_PATH)
    except FileNotFoundError:
        pass
    print("Initializing blank blockchain...", file=sys.stderr)
    bs = BlockchainStorage(DATABASE_PATH)
    wallets = bs.create_genesis()
    bs.make_random_transactions(100, wallets)
    for i in range(5):
        block = bs.prepare_mineable_block(wallets[0])
        print("Mining block %d..." % (i + 1), file=sys.stderr)
        block.solve_hash_challenge(16)
        bs.receive_block(block)
        bs.make_random_transactions(100, wallets)
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
