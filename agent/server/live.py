"""Coalesced dashboard notifications after durable event delivery."""

import asyncio
import json
import time
from contextlib import asynccontextmanager


class LiveUpdates:
    def __init__(self, max_clients: int = 16):
        self.revision = 0
        self.max_clients = max_clients
        self._clients: set[asyncio.Queue] = set()

    def notify(self):
        self.revision += 1
        for queue in self._clients:
            if queue.empty():
                queue.put_nowait(True)

    async def on_event(self, event):
        self.notify()

    @asynccontextmanager
    async def subscribe(self):
        if len(self._clients) >= self.max_clients:
            raise RuntimeError("Too many live dashboard connections")
        queue = asyncio.Queue(maxsize=1)
        self._clients.add(queue)
        try:
            yield queue
        finally:
            self._clients.discard(queue)

    def frame(self) -> str:
        data = json.dumps({"revision": self.revision, "time": time.time()})
        return f"event: change\ndata: {data}\n\n"
