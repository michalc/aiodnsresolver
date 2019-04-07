import asyncio
import ipaddress
import socket
import unittest
from unittest.mock import (
    MagicMock,
    Mock,
    patch,
    call,
)

from aiofastforward import (
    FastForward,
)

from aiodnsresolver import (
    TYPES,
    RESPONSE,
    DoesNotExist,
    Message,
    Resolver,
    ResourceRecord,
    pack,
    parse,
    memoize_expires_at,
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


class TestResolverIntegration(unittest.TestCase):
    """ Tests that run a controllable nameserver locally, mocking access to
    `/ect/resolve.conf` so this one is used by the resolver
    """

    def add_async_cleanup(self, loop, coroutine):
        self.addCleanup(loop.run_until_complete, coroutine())

    @async_test
    async def test_a_query(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record_1 = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            reponse_record_2 = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=41-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.124.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record_1, reponse_record_2), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve = Resolver()
            res_1 = await resolve('my.domain', TYPES.A)

            self.assertEqual(len(queried_names), 1)
            self.assertEqual(queried_names[0].lower(), b'my.domain')
            self.assertEqual(str(res_1[0]), '123.100.123.1')
            self.assertEqual(res_1[0].ttl(loop.time()), 20.0)
            self.assertEqual(str(res_1[1]), '123.100.124.1')
            self.assertEqual(res_1[1].ttl(loop.time()), 40.0)

            await forward(19.5)
            self.assertEqual(res_1[0].ttl(loop.time()), 0.5)

            res_2 = await resolve('my.domain', TYPES.A)
            self.assertEqual(len(queried_names), 1)
            self.assertEqual(str(res_2[0]), '123.100.123.1')
            self.assertEqual(res_2[0].ttl(loop.time()), 0.5)

            await forward(0.5)
            res_3 = await resolve('my.domain', TYPES.A)
            self.assertEqual(len(queried_names), 2)
            self.assertEqual(queried_names[1].lower(), b'my.domain')
            self.assertEqual(str(res_3[0]), '123.100.123.2')
            self.assertEqual(res_3[0].ttl(loop.time()), 19.0)

            self.assertNotEqual(queried_names[0], queried_names[1])


class TestResolverEndToEnd(unittest.TestCase):
    """ Tests that query current real nameserver(s) for real domains
    """

    @async_test
    async def test_a_query(self):
        loop = asyncio.get_event_loop()
        resolve = Resolver()
        res = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertIsInstance(res[0].ttl(loop.time()), float)
        self.assertTrue(0 <= res[0].ttl(loop.time()) <= 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_query_multiple(self):
        resolve = Resolver()
        res = await resolve('charemza.name', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertIsInstance(res[1], ipaddress.IPv4Address)
        self.assertNotEqual(res[0], res[1])

    @async_test
    async def test_a_query_twice_sequential(self):
        resolve = Resolver()
        res_a = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res_a[0], ipaddress.IPv4Address)

        res_b = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res_b[0], ipaddress.IPv4Address)

    @async_test
    async def test_a_query_twice_concurrent(self):
        resolve = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        res_b = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        self.assertIsInstance((await res_a)[0], ipaddress.IPv4Address)
        self.assertIsInstance((await res_b)[0], ipaddress.IPv4Address)
        self.assertEqual(await res_a, await res_b)

    @async_test
    async def test_a_query_different_concurrent(self):
        resolve = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        res_b = asyncio.ensure_future(resolve('charemza.name', TYPES.A))
        self.assertIsInstance((await res_a)[0], ipaddress.IPv4Address)
        self.assertIsInstance((await res_b)[0], ipaddress.IPv4Address)
        self.assertNotEqual(res_a, res_b)

    @async_test
    async def test_aaaa_query(self):
        loop = asyncio.get_event_loop()
        resolve = Resolver()
        res = await resolve('www.google.com', TYPES.AAAA)
        self.assertIsInstance(res[0], ipaddress.IPv6Address)
        self.assertIsInstance(res[0].ttl(loop.time()), float)
        self.assertTrue(0 <= res[0].ttl(loop.time()) <= 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_query_not_exists(self):
        resolve = Resolver()
        with self.assertRaises(DoesNotExist):
            res = await resolve('doenotexist.charemza.name', TYPES.A)

    @async_test
    async def test_aaaa_query_not_exists(self):
        resolve = Resolver()

        with self.assertRaises(DoesNotExist):
            res = await resolve('doenotexist.charemza.name', TYPES.AAAA)

    @async_test
    async def test_a_query_cname(self):
        resolve = Resolver()
        res = await resolve('support.dnsimple.com', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)

    @async_test
    async def test_localhost_a(self):
        loop = asyncio.get_event_loop()
        resolve = Resolver()
        res = await resolve('localhost', TYPES.A)
        self.assertIsInstance(res, tuple)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertEqual(str(res[0]), '127.0.0.1')
        self.assertEqual(res[0].ttl(loop.time()), 0)

    @async_test
    async def test_localhost_aaaa(self):
        loop = asyncio.get_event_loop()
        resolve = Resolver()
        res = await resolve('localhost', TYPES.AAAA)
        self.assertIsInstance(res, tuple)
        self.assertIsInstance(res[0], ipaddress.IPv6Address)
        self.assertEqual(str(res[0]), '::1')
        self.assertEqual(res[0].ttl(loop.time()), 0)


class TestMemoizeExpiresAt(unittest.TestCase):
    """ Test the memoize_expires_at function

    This is testing private implementation details. ideally, the tests would
    assert on public behaviour of the resolver
    """

    @async_test
    async def test_identical_concurrent_memoized_coroutine(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        ttls = [2, 1]

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            # Allow to another task to run
            await asyncio.sleep(0)
            return 'value'

        memoized = memoize_expires_at(func, lambda _: 100)

        with FastForward(loop) as forward:
            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

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
            return kwargs['b']

        memoized = memoize_expires_at(func, lambda _: 100)

        with FastForward(loop) as forward:
            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_a'))
            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_b'))

            task_a_result = await task_a
            task_b_result = await task_b

        self.assertEqual(task_a_result, 'val_b_a')
        self.assertEqual(task_b_result, 'val_b_b')
        self.assertEqual(mock.mock_calls, [
            call(10, 20, a='val_a', b='val_b_a'),
            call(10, 20, a='val_a', b='val_b_b'),
        ])

    @async_test
    async def test_identical_sequential_memoized(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        results = ['b', 'a']

        with FastForward(loop) as forward:
            async def func(*args, **kwargs):
                mock(*args, **kwargs)
                return results.pop()

            memoized = memoize_expires_at(func, lambda _: 100)

            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
            task_a_result = await task_a

            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

            task_b_result = await task_b

        self.assertEqual(task_a_result, 'a')
        self.assertEqual(task_b_result, 'a')
        self.assertEqual(mock.mock_calls, [
            call(10, 20, a='val_a', b='val_b'),
        ])

    @async_test
    async def test_identical_sequential_invalidate(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        results = [4, 3, 2, 1]

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            return results.pop()

        memoized = memoize_expires_at(func, lambda result: result)

        with FastForward(loop) as forward:
            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_a'))
            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_b'))
            task_a_result = await task_a
            task_b_result = await task_b

            await forward(1)
            task_c = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_a'))
            task_d = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b_b'))
            task_c_result = await task_c
            task_d_result = await task_d

            self.assertEqual(task_c_result, 3)
            self.assertEqual(task_d_result, 2)
            self.assertEqual(mock.mock_calls, [
                call(10, 20, a='val_a', b='val_b_a'),
                call(10, 20, a='val_a', b='val_b_b'),
                call(10, 20, a='val_a', b='val_b_a'),
            ])

    @async_test
    async def test_identical_sequential_with_sleep_invalidate(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        results = [3, 2, 1]

        async def func(*args, **kwargs):
            await asyncio.sleep(0.5)
            mock(*args, **kwargs)
            return results.pop()

        memoized = memoize_expires_at(func, lambda result: result)

        with FastForward(loop) as forward:
            forward_0_5 = forward(0.5)
            result_a = await memoized(10, 20, a='val_a', b='val_b')
            result_b = await memoized(10, 20, a='val_a', b='val_b')
            await forward_0_5

            forward_1 = forward(1)
            result_c = await memoized(10, 20, a='val_a', b='val_b')
            await forward_1

            self.assertEqual(result_a, 1)
            self.assertEqual(result_b, 1)
            self.assertEqual(result_c, 2)
            self.assertEqual(mock.mock_calls, [
                call(10, 20, a='val_a', b='val_b'),
                call(10, 20, a='val_a', b='val_b'),
            ])

    @async_test
    async def test_identical_concurrent_memoized_exception(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        results = ['b', 'a']

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            # Yield so the other task can run
            await asyncio.sleep(0)
            raise Exception(results.pop())

        memoized = memoize_expires_at(func, lambda _: 100)

        with FastForward(loop) as forward:
            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

            with self.assertRaisesRegex(Exception, 'a'):
                await task_a

            with self.assertRaisesRegex(Exception, 'a'):
                await task_b

        self.assertEqual(mock.mock_calls, [call(10, 20, a='val_a', b='val_b')])

    @async_test
    async def test_identical_sequential_not_memoized_exception(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        results = ['b', 'a']

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            # Yield so the other task can run
            await asyncio.sleep(0)
            raise Exception(results.pop())

        memoized = memoize_expires_at(func, lambda _: 100)

        with FastForward(loop) as forward:
            task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

            with self.assertRaisesRegex(Exception, 'a'):
                await task_a

            task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))

            with self.assertRaisesRegex(Exception, 'b'):
                await task_b

        self.assertEqual(mock.mock_calls, [
            call(10, 20, a='val_a', b='val_b'),
            call(10, 20, a='val_a', b='val_b'),
        ])

    @async_test
    async def test_identical_concurrent_memoized_cancelled(self):
        loop = asyncio.get_event_loop()
        mock = Mock()
        called = asyncio.Event()

        async def func(*args, **kwargs):
            mock(*args, **kwargs)
            called.set()
            await asyncio.Future()

        memoized = memoize_expires_at(func, lambda _: 100)

        task_a = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        task_b = asyncio.ensure_future(memoized(10, 20, a='val_a', b='val_b'))
        await called.wait()
        task_a.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await task_b


class TestTimeout(unittest.TestCase):
    """ Test the timeout context manager

    This is testing private implementation details. ideally, the tests would
    assert on public behaviour of the resolver
    """

    @async_test
    async def test_shorter_than_timeout_not_raises(self):
            loop = asyncio.get_event_loop()

            async def worker():
                with timeout(1):
                    await asyncio.sleep(0.5)

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(0.5)
                await task

    @async_test
    async def test_longer_than_timeout_raises_timeout_error(self):
            loop = asyncio.get_event_loop()

            async def worker():
                with timeout(1):
                    await asyncio.sleep(1.5)

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(1)
                with self.assertRaises(asyncio.TimeoutError):
                    await task

    @async_test
    async def test_cancel_raises_cancelled_error(self):
            loop = asyncio.get_event_loop()

            async def worker():
                with timeout(1):
                    await asyncio.sleep(0.5)

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(0.25)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

    @async_test
    async def test_exception_propagates(self):
            loop = asyncio.get_event_loop()

            async def worker():
                with timeout(2):
                    raise Exception('inner')

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(1)
                with self.assertRaisesRegex(Exception, 'inner'):
                    await task

    @async_test
    async def test_cleanup(self):
            loop = asyncio.get_event_loop()
            cleanup = asyncio.Event()

            async def worker():
                with timeout(1):
                    try:
                        await asyncio.sleep(2)
                    except asyncio.CancelledError:
                        cleanup.set()
                        raise

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(1)
                with self.assertRaises(asyncio.TimeoutError):
                    await task

                self.assertTrue(cleanup.is_set())

    @async_test
    async def test_ignore_timeout(self):
            loop = asyncio.get_event_loop()
            ignored = asyncio.Event()

            async def worker():
                with timeout(1):
                    try:
                        await asyncio.sleep(2)
                    except asyncio.CancelledError:
                        # Swallow the exception
                        pass
                ignored.set()

            with FastForward(loop) as forward:
                task = asyncio.ensure_future(worker())

                await forward(1)
                await task
                self.assertTrue(ignored.is_set())


async def start_nameserver(get_response):
    loop = asyncio.get_event_loop()

    def mock_open(file_name, _):
        lines = \
            ['127.0.0.1 localhost'] if file_name == '/etc/hosts' else \
            ['nameserver 127.0.0.1']

        context_manager = MagicMock()
        context_manager.__enter__.return_value = lines
        context_manager.__exit__.return_value = False
        return context_manager

    patched_open = patch('aiodnsresolver.open', side_effect=mock_open)
    patched_open.start()

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', 53))

    async def server():
        try:
            while True:
                data, addr = await recvfrom(loop, sock, 512)
                asyncio.ensure_future(client_task(data, addr))
        except asyncio.CancelledError:
            pass
        except BaseException as exception:
            print(exception)

    async def client_task(data, addr):
        response = await get_response(data)
        await sendto_all(loop, sock, response, addr)

    server_task = asyncio.ensure_future(server())

    async def stop():
        patched_open.stop()
        server_task.cancel()
        await asyncio.sleep(0)
        sock.close()

    return stop


# recvfrom/ sendto for nonblocking sockets for use in asyncio doesn't seem to
# be part of the standard library, and not wanting the inflexibility of using
# the streams/protocol/datagram endpoint framework

async def recvfrom(loop, sock, max_bytes):
    fileno = sock.fileno()
    result = asyncio.Future()

    def read_without_reader():
        try:
            (data, addr) = sock.recvfrom(max_bytes)
        except BlockingIOError:
            loop.add_reader(fileno, read_with_reader)
        except BaseException as exception:
            if not result.cancelled():
                result.set_exception(exception)
        else:
            result.set_result((data, addr))

    def read_with_reader():
        try:
            (data, addr) = sock.recvfrom(max_bytes)
        except BlockingIOError:
            pass
        except BaseException as exception:
            loop.remove_reader(fileno)
            if not result.cancelled():
                result.set_exception(exception)
        else:
            loop.remove_reader(fileno)
            result.set_result((data, addr))

    read_without_reader()

    try:
        return await result
    except asyncio.CancelledError:
        loop.remove_reader(fileno)
        raise


async def sendto(loop, sock, data, addr):
    fileno = sock.fileno()
    result = asyncio.Future()

    def write_without_reader():
        try:
            bytes_sent = sock.sendto(data, addr)
        except BlockingIOError:
            loop.add_witer(fileno, write_with_writer)
        except BaseException as exception:
            if not result.cancelled():
                result.set_exception(exception)
        else:
            result.set_result(bytes_sent)

    def write_with_writer():
        try:
            bytes_sent = sock.sendto(data, addr)
        except BlockingIOError:
            pass
        except BaseException as exception:
            loop.remove_reader(fileno)
            if not result.cancelled():
                result.set_exception(exception)
        else:
            loop.remove_reader(fileno)
            result.set_result(bytes_sent)

    write_without_reader()

    try:
        return await result
    except asyncio.CancelledError:
        loop.remove_reader(fileno)
        raise


async def sendto_all(loop, sock, data, addr):
    bytes_sent = 0
    while bytes_sent != len(data):
        bytes_sent += await sendto(loop, sock, data[bytes_sent:], addr)
