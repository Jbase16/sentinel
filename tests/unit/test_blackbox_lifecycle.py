import asyncio

from core.data.blackbox import BlackBox


def test_sync_fire_and_forget_is_retained_until_async_drain():
    writes: list[str] = []
    blackbox = BlackBox()

    async def write(value: str) -> None:
        writes.append(value)

    blackbox.fire_and_forget(write, "retained")

    assert blackbox._worker_task is None
    assert blackbox._queue.qsize() == 1

    async def drain() -> None:
        await blackbox.flush()
        await blackbox.shutdown()

    asyncio.run(drain())

    assert writes == ["retained"]
    assert blackbox._queue.empty()


def test_shutdown_without_pending_writes_does_not_start_worker():
    blackbox = BlackBox()

    asyncio.run(blackbox.shutdown())

    assert blackbox._worker_task is None
    assert blackbox._stopped is True


def test_flush_waits_for_write_already_in_progress():
    blackbox = BlackBox()

    async def exercise() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def write() -> None:
            started.set()
            await release.wait()

        blackbox.fire_and_forget(write)
        await started.wait()

        flush_task = asyncio.create_task(blackbox.flush())
        await asyncio.sleep(0)
        assert not flush_task.done()

        release.set()
        await flush_task
        await blackbox.shutdown()

    asyncio.run(exercise())
