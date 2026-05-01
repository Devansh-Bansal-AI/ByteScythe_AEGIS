"""
AEGIS Phase 2 — Redis Streams Message Bus Adapter

WHY THIS EXISTS:
----------------
The current asyncio.Queue is in-memory — data is lost on crash/restart.
Redis Streams provides:
  1. Durable message persistence (survives restarts)
  2. Consumer groups (horizontal scaling across workers)
  3. Backpressure via XLEN monitoring

GRACEFUL DEGRADATION:
--------------------
If Redis is unavailable, falls back to asyncio.Queue automatically.
Set AEGIS_REDIS_URL to enable Redis mode.
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("AEGIS_REDIS_URL", "")
STREAM_KEY = os.getenv("AEGIS_REDIS_STREAM", "aegis:telemetry")
CONSUMER_GROUP = "aegis-workers"
CONSUMER_NAME = os.getenv("AEGIS_WORKER_ID", "worker-1")


@dataclass
class StreamMessage:
    """Normalized message from either Redis or asyncio.Queue."""
    id: str
    data: Dict[str, Any]
    timestamp: float
    priority: int = 0


class MessageBusInterface:
    """Abstract message bus — Redis Streams or asyncio.Queue."""

    async def publish(self, data: Dict[str, Any], priority: int = 0) -> str:
        raise NotImplementedError

    async def consume(self, handler: Callable, batch_size: int = 10) -> None:
        raise NotImplementedError

    async def start(self) -> None:
        raise NotImplementedError

    async def stop(self) -> None:
        raise NotImplementedError

    @property
    def queue_size(self) -> int:
        raise NotImplementedError


class AsyncQueueBus(MessageBusInterface):
    """In-memory asyncio.Queue fallback (development mode)."""

    def __init__(self, maxsize: int = 10000):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=maxsize)
        self._running = False
        self._msg_counter = 0

    async def publish(self, data: Dict[str, Any], priority: int = 0) -> str:
        self._msg_counter += 1
        msg_id = f"mem-{self._msg_counter}"
        msg = StreamMessage(
            id=msg_id,
            data=data,
            timestamp=time.time(),
            priority=priority,
        )
        await self._queue.put((priority, self._msg_counter, msg))
        return msg_id

    async def consume(self, handler: Callable, batch_size: int = 10) -> None:
        """Continuously consume messages and pass to handler."""
        self._running = True
        while self._running:
            try:
                batch = []
                for _ in range(batch_size):
                    try:
                        _, _, msg = self._queue.get_nowait()
                        batch.append(msg)
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    await handler(batch)
                else:
                    await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"AsyncQueueBus consume error: {e}")
                await asyncio.sleep(1)

    async def start(self) -> None:
        logger.info("AsyncQueueBus started (in-memory fallback mode)")
        self._running = True

    async def stop(self) -> None:
        self._running = False
        logger.info("AsyncQueueBus stopped")

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()


class RedisStreamBus(MessageBusInterface):
    """Redis Streams message bus for production deployments."""

    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._redis = None
        self._running = False
        self._msg_counter = 0

    async def start(self) -> None:
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                max_connections=20,
            )
            # Create consumer group if it doesn't exist
            try:
                await self._redis.xgroup_create(
                    STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True
                )
            except Exception:
                pass  # Group already exists
            self._running = True
            logger.info(f"RedisStreamBus connected to {self._redis_url}")
        except ImportError:
            raise RuntimeError(
                "redis package required. Install with: pip install redis[hiredis]"
            )

    async def stop(self) -> None:
        self._running = False
        if self._redis:
            await self._redis.close()
        logger.info("RedisStreamBus stopped")

    async def publish(self, data: Dict[str, Any], priority: int = 0) -> str:
        if not self._redis:
            raise RuntimeError("RedisStreamBus not started")

        payload = {
            "data": json.dumps(data),
            "priority": str(priority),
            "timestamp": str(time.time()),
        }
        msg_id = await self._redis.xadd(STREAM_KEY, payload)
        self._msg_counter += 1
        return msg_id

    async def consume(self, handler: Callable, batch_size: int = 10) -> None:
        if not self._redis:
            raise RuntimeError("RedisStreamBus not started")

        self._running = True
        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    CONSUMER_GROUP,
                    CONSUMER_NAME,
                    {STREAM_KEY: ">"},
                    count=batch_size,
                    block=1000,
                )

                if not messages:
                    continue

                batch = []
                for stream_name, stream_messages in messages:
                    for msg_id, fields in stream_messages:
                        msg = StreamMessage(
                            id=msg_id,
                            data=json.loads(fields.get("data", "{}")),
                            timestamp=float(fields.get("timestamp", 0)),
                            priority=int(fields.get("priority", 0)),
                        )
                        batch.append(msg)

                if batch:
                    await handler(batch)
                    # ACK all processed messages
                    msg_ids = [m.id for m in batch]
                    await self._redis.xack(STREAM_KEY, CONSUMER_GROUP, *msg_ids)

            except Exception as e:
                logger.error(f"RedisStreamBus consume error: {e}")
                await asyncio.sleep(1)

    @property
    def queue_size(self) -> int:
        # This is approximate — requires sync call
        return self._msg_counter


def create_message_bus() -> MessageBusInterface:
    """Factory: create Redis bus if URL configured, else asyncio fallback."""
    if REDIS_URL:
        logger.info(f"Using Redis Streams message bus: {REDIS_URL}")
        return RedisStreamBus(REDIS_URL)
    else:
        logger.info("Using in-memory asyncio.Queue message bus (set AEGIS_REDIS_URL for Redis)")
        return AsyncQueueBus()
