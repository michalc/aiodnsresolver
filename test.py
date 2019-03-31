import asyncio
import ipaddress
import unittest
from unittest.mock import (
    Mock,
    call,
)

from aiofastforward import (
    FastForward,
)

from aiodnsresolver import (
    types,
    Resolver,
    memoize_concurrent,
    timeout,
)


def async_test(func):
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


def until_called(num_times):
    num_times_called = 0
    future = asyncio.Future()

    def func():
        nonlocal num_times_called
        num_times_called += 1
        if num_times_called == num_times:
            future.set_result(None)
        return future

    return func


class TestResolver(unittest.TestCase):

    @async_test
    async def test_a_query(self):
        resolve = Resolver()
        res = await resolve('www.google.com', types.A)
        self.assertIsInstance(ipaddress.ip_address(res), ipaddress.IPv4Address)

    @async_test
    async def test_a_query_twice_sequential(self):
        resolve = Resolver()
        res_a = await resolve('www.google.com', types.A)
        self.assertIsInstance(ipaddress.ip_address(res_a), ipaddress.IPv4Address)

        res_b = await resolve('www.google.com', types.A)
        self.assertIsInstance(ipaddress.ip_address(res_b), ipaddress.IPv4Address)

    @async_test
    async def test_a_query_twice_concurrent(self):
        resolve = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', types.A))
        res_b = asyncio.ensure_future(resolve('www.google.com', types.A))
        self.assertIsInstance(ipaddress.ip_address(await res_a), ipaddress.IPv4Address)
        self.assertIsInstance(ipaddress.ip_address(await res_b), ipaddress.IPv4Address)

    @async_test
    async def test_a_query_different_concurrent(self):
        resolve = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', types.A))
        res_b = asyncio.ensure_future(resolve('charemza.name', types.A))
        self.assertIsInstance(ipaddress.ip_address(await res_a), ipaddress.IPv4Address)
        self.assertIsInstance(ipaddress.ip_address(await res_b), ipaddress.IPv4Address)

    @async_test
    async def test_aaaa_query(self):
        resolve = Resolver()
        res = await resolve('www.google.com', types.AAAA)
        self.assertIsInstance(ipaddress.ip_address(res), ipaddress.IPv6Address)

    @async_test
    async def test_a_query_not_exists(self):
        resolve = Resolver()
        with self.assertRaises(Exception):
            res = await resolve('doenotexist.charemza.name', types.A)

    @async_test
    async def test_aaaa_query_not_exists(self):
        resolve = Resolver()

        with self.assertRaises(Exception):
            res = await resolve('doenotexist.charemza.name', types.AAAA)

    @async_test
    async def test_a_query_cname(self):
        resolve = Resolver()
        res = await resolve('support.dnsimple.com', types.A)
        self.assertIsInstance(ipaddress.ip_address(res), ipaddress.IPv4Address)


class TestMemoizeConcurrent(unittest.TestCase):

    @async_test
    async def test_identical_concurrent_memoized_coroutine(self):
        loop = asyncio.get_event_loop()
        mock = Mock()

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            # Yield so the other task can run
            await asyncio.sleep(0)
            return 'value'

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

        task_a_result = await task_a
        task_b_result = await task_b
        self.assertEqual(task_a_result, 'value')
        self.assertEqual(task_b_result, 'value')
        self.assertEqual(mock.mock_calls, [call(10, 20, a='val_a', b='val_b')])

    @async_test
    async def test_identical_concurrent_memoized_future(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        future = asyncio.Future()

        def func(*args, **kwargs):
            mock(*args, **kwargs)
            return future

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

        await asyncio.sleep(0)
        future.set_result('value')

        task_a_result = await task_a
        task_b_result = await task_b
        self.assertEqual(task_a_result, 'value')
        self.assertEqual(task_b_result, 'value')
        self.assertEqual(mock.mock_calls, [call(10, 20, a='val_a', b='val_b')])

    @async_test
    async def test_different_concurrent_not_memoized(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        func_done = asyncio.Event()
        until_called_twice = until_called(num_times=2)

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            await until_called_twice()
            return 'value'

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_d'))

        task_a_result = await task_a
        task_b_result = await task_b
        self.assertEqual(task_a_result, 'value')
        self.assertEqual(task_b_result, 'value')
        self.assertEqual(mock.mock_calls, [
            call(10, 20, a='val_a', b='val_b'),
            call(10, 20, a='val_a', b='val_d'),
        ])

    @async_test
    async def test_identical_sequential_not_memoized(self):
        loop = asyncio.get_event_loop()
        mock = Mock()

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            return 'value'

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_a_result = await task_a

        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

        task_b_result = await task_b
        self.assertEqual(task_a_result, 'value')
        self.assertEqual(task_b_result, 'value')
        self.assertEqual(mock.mock_calls, [
            call(10, 20, a='val_a', b='val_b'),
            call(10, 20, a='val_a', b='val_b'),
        ])

    @async_test
    async def test_identical_concurrent_memoized_exception(self):
        loop = asyncio.get_event_loop()
        mock = Mock()

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            # Yield so the other task can run
            await asyncio.sleep(0)
            raise Exception('inner')

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

        with self.assertRaisesRegex(Exception, 'inner'):
            await task_a

        with self.assertRaisesRegex(Exception, 'inner'):
            await task_b

        self.assertEqual(mock.mock_calls, [call(10, 20, a='val_a', b='val_b')])

    @async_test
    async def test_identical_concurrent_memoized_cancelled(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        called = asyncio.Event()

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            called.set()
            await asyncio.Future()

        memoized = memoize_concurrent(func)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        await called.wait()
        task_a.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await task_b
