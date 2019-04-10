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
    recvfrom,
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
            res_1 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)

            self.assertEqual(len(queried_names), 1)
            self.assertEqual(queried_names[0].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_1[0]), '123.100.123.1')
            self.assertEqual(res_1[0].ttl(loop.time()), 20.0)
            self.assertEqual(str(res_1[1]), '123.100.124.1')
            self.assertEqual(res_1[1].ttl(loop.time()), 40.0)

            await forward(19.5)
            self.assertEqual(res_1[0].ttl(loop.time()), 0.5)

            res_2 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 1)
            self.assertEqual(str(res_2[0]), '123.100.123.1')
            self.assertEqual(res_2[0].ttl(loop.time()), 0.5)

            await forward(0.5)
            res_3 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 2)
            self.assertEqual(queried_names[1].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_3[0]), '123.100.123.2')
            self.assertEqual(res_3[0].ttl(loop.time()), 19.0)

            self.assertNotEqual(queried_names[0], queried_names[1])

    @async_test
    async def test_concurrent_identical_a_query_not_made(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            # Yield to the other task
            await asyncio.sleep(0)
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))

        res_1 = await res_1_task
        res_2 = await res_2_task

        self.assertEqual(str(res_1[0]), '123.100.123.1')
        self.assertEqual(str(res_2[0]), '123.100.123.1')
        self.assertEqual(len(queried_names), 1)

    @async_test
    async def test_concurrent_different_a_query_made(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            # Yield to the other task
            await asyncio.sleep(0)
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('other.domain', TYPES.A))

        res_1 = await res_1_task
        res_2 = await res_2_task

        self.assertEqual(str(res_1[0]), '123.100.123.1')
        self.assertEqual(str(res_2[0]), '123.100.123.2')
        self.assertEqual(len(queried_names), 2)
        self.assertEqual(queried_names[0].lower(), b'my.domain')
        self.assertEqual(queried_names[1].lower(), b'other.domain')

    @async_test
    async def test_cache_expiry_different_queries_independent(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            # Yield to the other task
            await asyncio.sleep(0)
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve = Resolver()
            res_1 = await resolve('my.domain', TYPES.A)
            res_2 = await resolve('other.domain', TYPES.A)
            self.assertEqual(len(queried_names), 2)

            await forward(19)
            res_1 = await resolve('my.domain', TYPES.A)
            res_2 = await resolve('other.domain', TYPES.A)
            self.assertEqual(len(queried_names), 3)
            self.assertEqual(queried_names[2].lower(), b'other.domain')

    @async_test
    async def test_concurrent_identical_exception_identical(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            # Yield to the other task
            await asyncio.sleep(0)
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=b'bad-ip-address',
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))

        with self.assertRaises(ipaddress.AddressValueError):
            res_1 = await res_1_task

        with self.assertRaises(ipaddress.AddressValueError):
            res_2 = await res_2_task

        self.assertEqual(len(queried_names), 1)

    @async_test
    async def test_sequential_identical_exception_not_cached(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            # Yield to the other task
            await asyncio.sleep(0)
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=\
                    b'bad-ip-address' if len(queried_names) == 1 else \
                    ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed
                ,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()

        with self.assertRaises(ipaddress.AddressValueError):
            await resolve('my.domain', TYPES.A)

        res_2 = await resolve('my.domain', TYPES.A)
        self.assertEqual(len(queried_names), 2)
        self.assertEqual(str(res_2[0]), '123.100.123.2')

    @async_test
    async def test_cancel_can_run_next(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future()]
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)
            await response_blockers[len(queried_names) - 1]

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        response_blockers[0].cancel()
        await asyncio.sleep(0)

        res_1_task.cancel()
        await asyncio.sleep(0)

        response_blockers[1].set_result(None)
        res_2 = await resolve('my.domain', TYPES.A)
        self.assertEqual(str(res_2[0]), '123.100.123.2')

    @async_test
    async def test_concurrent_tasks_first_cancel_not_cancel_second(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future(), asyncio.Future()]
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)
            await response_blockers[len(queried_names) - 1]

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        await asyncio.sleep(0)

        res_1_task.cancel()
        await asyncio.sleep(0)
        with self.assertRaises(asyncio.CancelledError):
            await res_1_task

        response_blockers[1].set_result(None)
        res_2 = await res_2_task
        self.assertEqual(str(res_2[0]), '123.100.123.2')

    @async_test
    async def test_concurrent_tasks_second_cancel_not_cancel_others(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future()]
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)
            await response_blockers[len(queried_names) - 1]

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_3_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))

        res_2_task.cancel()
        await asyncio.sleep(0)
        with self.assertRaises(asyncio.CancelledError):
            await res_2_task

        response_blockers[0].set_result(None)
        res_1 = await res_1_task
        res_3 = await res_3_task
        self.assertEqual(len(queried_names), 1)
        self.assertEqual(str(res_1[0]), '123.100.123.1')
        self.assertEqual(str(res_3[0]), '123.100.123.1')

    @async_test
    async def test_concurrent_tasks_first_two_cancel_not_cancel_final(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future()]
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)
            await response_blockers[len(queried_names) - 1]

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_3_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        await asyncio.sleep(0)
        response_blockers[0].set_result(None)

        res_1_task.cancel()
        res_2_task.cancel()
        await asyncio.sleep(0)
        with self.assertRaises(asyncio.CancelledError):
            await res_1_task
        with self.assertRaises(asyncio.CancelledError):
            await res_2_task

        response_blockers[1].set_result(None)
        res_3 = await res_3_task
        self.assertEqual(len(queried_names), 2)
        self.assertEqual(str(res_3[0]), '123.100.123.2')

    @async_test
    async def test_udp_timeout_try_again(self):
        loop = asyncio.get_event_loop()
        requests = [asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event()]
        response_blockers = [asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event()]
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            requests[len(queried_names)].set()
            queried_names.append(query.qd[0].name)
            await response_blockers[len(queried_names)].wait()

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve = Resolver()
            res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
            await requests[0].wait()
            self.assertEqual(len(queried_names), 1)
            await forward(0.5)
            await requests[1].wait()
            self.assertEqual(len(queried_names), 2)
            await forward(0.5)
            await requests[2].wait()
            self.assertEqual(len(queried_names), 3)
            await forward(0.5)
            await requests[3].wait()
            self.assertEqual(len(queried_names), 4)
            response_blockers[4].set()

            res_2 = await resolve('my.domain', TYPES.A)
            self.assertEqual(str(res_2[0]), '123.100.123.4')

    @async_test
    async def test_udp_timeout_eventually_fail(self):
        loop = asyncio.get_event_loop()
        blocker = asyncio.Event()
        request = asyncio.Event()

        async def get_response(query_data):
            query = parse(query_data)
            request.set()
            await blocker.wait()

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve = Resolver()
            res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
            await request.wait()
            await forward(2.5)

            with self.assertRaises(asyncio.TimeoutError):
                await res_1_task

    @async_test
    async def test_many_concurrent_queries_range(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future(), asyncio.Future()]

        async def get_response(query_data):
            query = parse(query_data)
            num = int(query.qd[0].name.split(b'-')[1])

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=5,
                rdata=ipaddress.IPv4Address('123.100.123.' + str(num)).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        tasks = [
            asyncio.ensure_future(resolve('my.domain-' + str((i + 1) % 255), TYPES.A))
            for i in range(1000)
        ]
        results = [
            str(result[0])
            for result in await asyncio.gather(*tasks)
        ]
        expected_results = [
            '123.100.123.' + str((i + 1) % 255)
            for i in range(1000)
        ]
        self.assertEqual(results, expected_results)

    @async_test
    async def test_many_concurrent_queries_identical_0_ttl(self):
        loop = asyncio.get_event_loop()
        response_blockers = [asyncio.Future(), asyncio.Future(), asyncio.Future()]
        num_queries = 0

        async def get_response(query_data):
            nonlocal num_queries
            num_queries += 1
            query = parse(query_data)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=0,
                rdata=ipaddress.IPv4Address('123.100.123.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve = Resolver()
        tasks = [
            asyncio.ensure_future(resolve('my.domain', TYPES.A))
            for i in range(100)
        ]
        results = [
            str(result[0])
            for result in await asyncio.gather(*tasks)
        ]
        expected_results = [
            '123.100.123.1'
            for i in range(100)
        ]
        self.assertEqual(results, expected_results)
        self.assertEqual(num_queries, 1)


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
    async def test_txt_query(self):
        resolve = Resolver()
        res = await resolve('charemza.name', TYPES.TXT)
        self.assertIn(b'google', res[0])

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
        client_tasks = []
        try:
            while True:
                data, addr = await recvfrom(loop, sock, 512)
                client_tasks.append(asyncio.ensure_future(client_task(data, addr)))
        except asyncio.CancelledError:
            pass
        except BaseException as exception:
            print(exception)
        finally:
            for task in client_tasks:
                task.cancel()

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

async def sendto(loop, sock, data, addr):
    fileno = sock.fileno()
    result = asyncio.Future()

    def write_without_writer():
        try:
            bytes_sent = sock.sendto(data, addr)
        except BlockingIOError:
            loop.add_witer(fileno, write_with_writer)
        except BaseException as exception:
            if not result.cancelled():
                result.set_exception(exception)
        else:
            if not result.cancelled():
                result.set_result(bytes_sent)

    def write_with_writer():
        try:
            bytes_sent = sock.sendto(data, addr)
        except BlockingIOError:
            pass
        except BaseException as exception:
            loop.remove_writer(fileno)
            if not result.cancelled():
                result.set_exception(exception)
        else:
            loop.remove_writer(fileno)
            if not result.cancelled():
                result.set_result(bytes_sent)

    write_without_writer()

    try:
        return await result
    except asyncio.CancelledError:
        loop.remove_writer(fileno)
        raise


async def sendto_all(loop, sock, data, addr):
    bytes_sent = await sendto(loop, sock, data, addr)
    while bytes_sent != len(data):
        bytes_sent += await sendto(loop, sock, data[bytes_sent:], addr)
