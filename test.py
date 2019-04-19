import asyncio
import ipaddress
import socket
import unittest
from unittest.mock import (
    MagicMock,
    patch,
)

import aiohttp
from aiohttp import web
from aiofastforward import (
    FastForward,
)

from aiodnsresolver import (
    TYPES,
    RESPONSE,
    DoesNotExist,
    Message,
    Resolver,
    ResolverError,
    ResourceRecord,
    pack,
    parse,
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, invalidate = Resolver()
            res_1 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)

            self.assertEqual(len(queried_names), 1)
            self.assertEqual(queried_names[0].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_1[0]), '123.100.123.1')
            self.assertEqual(res_1[0].expires_at, loop.time() + 20.0)
            self.assertEqual(str(res_1[1]), '123.100.124.1')
            self.assertEqual(res_1[1].expires_at, loop.time() + 40.0)

            await forward(19.5)
            self.assertEqual(res_1[0].expires_at, loop.time() + 0.5)

            res_2 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 1)
            self.assertEqual(str(res_2[0]), '123.100.123.1')
            self.assertEqual(res_2[0].expires_at, loop.time() + 0.5)

            await forward(0.5)
            res_3 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 2)
            self.assertEqual(queried_names[1].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_3[0]), '123.100.123.2')
            self.assertEqual(res_3[0].expires_at, loop.time() + 19.0)

            self.assertNotEqual(queried_names[0], queried_names[1])

            res_4 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 2)
            self.assertEqual(queried_names[1].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_4[0]), '123.100.123.2')

            invalidate()
            res_5 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 3)
            self.assertEqual(queried_names[2].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_5[0]), '123.100.123.3')

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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, _ = Resolver()
            await resolve('my.domain', TYPES.A)
            await resolve('other.domain', TYPES.A)
            self.assertEqual(len(queried_names), 2)

            await forward(19)
            await resolve('my.domain', TYPES.A)
            await resolve('other.domain', TYPES.A)
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
        res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))

        with self.assertRaises(ipaddress.AddressValueError):
            await res_1_task

        with self.assertRaises(ipaddress.AddressValueError):
            await res_2_task

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
                rdata=b'bad-ip-address' if len(queried_names) == 1 else
                ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()

        with self.assertRaises(ipaddress.AddressValueError):
            await resolve('my.domain', TYPES.A)

        res_2 = await resolve('my.domain', TYPES.A)
        self.assertEqual(len(queried_names), 2)
        self.assertEqual(str(res_2[0]), '123.100.123.2')

    @async_test
    async def test_bad_qid_ignored(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21-len(queried_names),
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            qid = query.qid + (1 if len(queried_names) == 1 else 0)
            response = Message(
                qid=qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
        res_1 = await resolve('my.domain', TYPES.A)

        self.assertEqual(str(res_1[0]), '123.100.123.2')
        self.assertEqual(len(queried_names), 2)

    @async_test
    async def test_bad_0x20_ignored(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=0,
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            lower = query.qd[0].name.lower()
            question = \
                query.qd[0]._replace(name=lower) if len(queried_names) == 1 else \
                query.qd[0]
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=(question,), an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
        res_1 = await resolve('my.domain', TYPES.A)

        self.assertEqual(str(res_1[0]), '123.100.123.2')
        self.assertEqual(len(queried_names), 2)

    @async_test
    async def test_short_response_ignored(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            if len(queried_names) == 1:
                return b'bad-data'

            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=0,
                rdata=ipaddress.IPv4Address('123.100.123.' + str(len(queried_names))).packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
        res_1 = await resolve('my.domain', TYPES.A)

        self.assertEqual(str(res_1[0]), '123.100.123.2')
        self.assertEqual(len(queried_names), 2)

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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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
        response_blockers = [asyncio.Event(), asyncio.Event(), asyncio.Event(),
                             asyncio.Event(), asyncio.Event()]
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, _ = Resolver()
            asyncio.ensure_future(resolve('my.domain', TYPES.A))
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
    async def test_udp_timeout_try_next_nameserver(self):
        loop = asyncio.get_event_loop()
        queried_names_53 = []

        with FastForward(loop) as forward:
            async def get_response_53(query_data):
                query = parse(query_data)
                queried_names_53.append(query.qd[0].name)
                await forward(0.5)
                await asyncio.Future()

            async def get_response_54(query_data):
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

            stop_nameserver_53 = await start_nameserver(53, get_response_53)
            self.add_async_cleanup(loop, stop_nameserver_53)
            stop_nameserver_54 = await start_nameserver(54, get_response_54)
            self.add_async_cleanup(loop, stop_nameserver_54)

            async def get_nameservers(_):
                yield (0.5, (ipaddress.ip_address('127.0.0.1'), 53))
                yield (0.5, (ipaddress.ip_address('127.0.0.1'), 54))

            resolve, _ = Resolver(get_nameservers=get_nameservers)

            res = await resolve('my.domain', TYPES.A)
            self.assertEqual(str(res[0]), '123.100.123.1')
            self.assertEqual(queried_names_53[0].lower(), b'my.domain')

    @async_test
    async def test_multiple_nameservers(self):
        loop = asyncio.get_event_loop()
        queried_names_53 = []
        queried_names_54 = []

        with FastForward(loop):
            async def get_response_53(query_data):
                query = parse(query_data)
                queried_names_53.append(query.qd[0].name)
                await asyncio.Future()

            async def get_response_54(query_data):
                query = parse(query_data)
                queried_names_54.append(query.qd[0].name)
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

            stop_nameserver_53 = await start_nameserver(53, get_response_53)
            self.add_async_cleanup(loop, stop_nameserver_53)
            stop_nameserver_54 = await start_nameserver(54, get_response_54)
            self.add_async_cleanup(loop, stop_nameserver_54)

            async def get_nameservers(_):
                yield (
                    0.5,
                    (ipaddress.ip_address('127.0.0.1'), 53),
                    (ipaddress.ip_address('127.0.0.1'), 54),
                )

            resolve, _ = Resolver(get_nameservers=get_nameservers)

            res = await resolve('my.domain', TYPES.A)
            self.assertEqual(str(res[0]), '123.100.123.1')
            self.assertEqual(queried_names_53[0].lower(), b'my.domain')
            self.assertEqual(queried_names_54[0].lower(), b'my.domain')

    @async_test
    async def test_udp_timeout_eventually_fail(self):
        loop = asyncio.get_event_loop()
        blocker = asyncio.Event()
        request = asyncio.Event()

        async def get_response(_):
            request.set()
            await blocker.wait()

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, _ = Resolver()
            res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
            await request.wait()
            await forward(2.5)

            with self.assertRaises(asyncio.TimeoutError):
                await res_1_task

    @async_test
    async def test_a_socket_error_fail_immediately(self):
        # No nameserver started
        self.addCleanup(patch_open())

        resolve, _ = Resolver()
        with self.assertRaises(ConnectionRefusedError):
            await resolve('my.domain', TYPES.A)

    @async_test
    async def test_many_concurrent_queries_range(self):
        loop = asyncio.get_event_loop()

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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver()
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

    @async_test
    async def test_aiohttp_resolver_integration(self):
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            if len(queried_names) == 1:
                reponse_records = (ResourceRecord(
                    name=query.qd[0].name,
                    qtype=TYPES.A,
                    qclass=1,
                    ttl=0,
                    rdata=ipaddress.IPv4Address('127.0.0.1').packed,
                ), )
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )
            elif len(queried_names) == 2:
                reponse_records = ()
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )
            else:
                reponse_records = ()
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=1,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )

            return pack(response)

        class AioHttpDnsResolver(aiohttp.abc.AbstractResolver):
            def __init__(self):
                super().__init__()
                self.resolver, self.clear_cache = Resolver()

            async def resolve(self, host, port=0, family=socket.AF_INET):
                # Use ipv4 unless requested otherwise
                # This is consistent with the default aiohttp + aiodns AsyncResolver
                record_type = \
                    TYPES.AAAA if family == socket.AF_INET6 else \
                    TYPES.A

                try:
                    ip_addresses = await self.resolver(host, record_type)
                except DoesNotExist as does_not_exist:
                    raise OSError(0, '{} does not exist'.format(host)) from does_not_exist
                except ResolverError as resolver_error:
                    raise OSError(0, '{} failed to resolve'.format(host)) from resolver_error

                return [{
                    'hostname': host,
                    'host': str(ip_address),
                    'port': port,
                    'family': family,
                    'proto': socket.IPPROTO_TCP,
                    'flags': socket.AI_NUMERICHOST,
                } for ip_address in ip_addresses]

            async def close(self):
                self.clear_cache()

        loop = asyncio.get_event_loop()
        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        async def handle_get(_):
            return web.Response(status=204)

        app = web.Application()
        app.add_routes([
            web.get('/page', handle_get)
        ])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8876)
        await site.start()
        self.add_async_cleanup(loop, runner.cleanup)

        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(use_dns_cache=False, resolver=AioHttpDnsResolver()),
        ) as session:
            async with await session.get('http://some-domain.com:8876/page') as result:
                self.assertEqual(result.status, 204)

            with self.assertRaisesRegex(
                    aiohttp.client_exceptions.ClientConnectorError,
                    'does not exist'):
                await session.get('http://other-domain.com:8876/page')

            with self.assertRaisesRegex(
                    aiohttp.client_exceptions.ClientConnectorError,
                    'failed to resolve'):
                await session.get('http://more-domain.com:8876/page')

    @async_test
    async def test_aiohttp_connector_integration(self):
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            queried_names.append(query.qd[0].name)

            if len(queried_names) == 1:
                reponse_records = (ResourceRecord(
                    name=query.qd[0].name,
                    qtype=TYPES.A,
                    qclass=1,
                    ttl=0,
                    rdata=ipaddress.IPv4Address('127.0.0.1').packed,
                ), )
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )
            elif len(queried_names) == 2:
                reponse_records = ()
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )
            else:
                reponse_records = ()
                response = Message(
                    qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=1,
                    qd=query.qd, an=reponse_records, ns=(), ar=(),
                )

            return pack(response)

        # Copyright 2013-2019 Nikolay Kim and Andrew Svetlov
        # SPDX-License-Identifier: Apache-2.0
        # Modified from https://github.com/aio-libs/aiohttp/blob/8b883f72b6bcc
        # 22a53199a8c4850be5dda837e22/aiohttp/connector.py

        import functools
        import ssl
        from ssl import (
            SSLContext,
        )
        from typing import (
            Any,
            Awaitable,
            Dict,
            List,
            Optional,
            Tuple,
            Type,
            Union,
            cast,
        )
        from aiohttp import (
            hdrs,
        )
        from aiohttp.client import (
            ClientTimeout,
        )
        from aiohttp.client_exceptions import (
            ClientConnectorCertificateError,
            ClientConnectorError,
            ClientConnectorSSLError,
            ClientHttpProxyError,
            ClientProxyConnectionError,
            ServerFingerprintMismatch,
            cert_errors,
            ssl_errors,
        )
        from aiohttp.client_proto import (
            ResponseHandler,
        )
        from aiohttp.client_reqrep import (
            SSL_ALLOWED_TYPES,
            ClientRequest,
            Fingerprint,
        )
        from aiohttp.connector import (
            _DNSCacheTable,
            BaseConnector,
            Connection,
            sentinel,
        )
        from aiohttp.helpers import (
            CeilTimeout,
            is_ip_address,
        )
        from aiohttp.http import (
            RESPONSES,
        )
        from aiohttp.locks import (
            EventResultOrError,
        )
        from aiohttp.resolver import (
            AbstractResolver,
            DefaultResolver,
        )
        import attr

        class TCPConnector(BaseConnector):
            """TCP connector.
            verify_ssl - Set to True to check ssl certifications.
            fingerprint - Pass the binary sha256
                digest of the expected certificate in DER format to verify
                that the certificate the server presents matches. See also
                https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning
            resolver - Enable DNS lookups and use this
                resolver
            use_dns_cache - Use memory cache for DNS lookups.
            ttl_dns_cache - Max seconds having cached a DNS entry, None forever.
            family - socket address family
            local_addr - local tuple of (host, port) to bind socket to
            keepalive_timeout - (optional) Keep-alive timeout.
            force_close - Set to True to force close and do reconnect
                after each request (and between redirects).
            limit - The total number of simultaneous connections.
            limit_per_host - Number of simultaneous connections to one host.
            enable_cleanup_closed - Enables clean-up closed ssl transports.
                                    Disabled by default.
            loop - Optional event loop.
            """

            def __init__(self, *,
                         use_dns_cache: bool = True, ttl_dns_cache: int = 10,
                         family: int = 0,
                         ssl: Union[None, bool, Fingerprint, SSLContext] = None,
                         local_addr: Optional[str] = None,
                         resolver: Optional[AbstractResolver] = None,
                         keepalive_timeout: Union[None, float, object] = sentinel,
                         force_close: bool = False,
                         limit: int = 100, limit_per_host: int = 0,
                         enable_cleanup_closed: bool = False,
                         loop: Optional[asyncio.AbstractEventLoop] = None):
                super().__init__(keepalive_timeout=keepalive_timeout,
                                 force_close=force_close,
                                 limit=limit, limit_per_host=limit_per_host,
                                 enable_cleanup_closed=enable_cleanup_closed,
                                 loop=loop)

                if not isinstance(ssl, SSL_ALLOWED_TYPES):
                    raise TypeError('ssl should be SSLContext, bool, Fingerprint, '
                                    'or None, got {!r} instead.'.format(ssl))
                self._ssl = ssl
                if resolver is None:
                    resolver = DefaultResolver(loop=self._loop)
                self._resolver = resolver

                self._use_dns_cache = use_dns_cache
                self._cached_hosts = _DNSCacheTable(ttl=ttl_dns_cache)
                self._throttle_dns_events = {}
                self._family = family
                self._local_addr = local_addr

            def close(self) -> Awaitable[None]:
                """Close all ongoing DNS calls."""
                for ev in self._throttle_dns_events.values():
                    ev.cancel()

                return super().close()

            @property
            def family(self) -> int:
                """Socket family like AF_INET."""
                return self._family

            @property
            def use_dns_cache(self) -> bool:
                """True if local DNS caching is enabled."""
                return self._use_dns_cache

            def clear_dns_cache(self,
                                host: Optional[str] = None,
                                port: Optional[int] = None) -> None:
                """Remove specified host/port or clear all dns local cache."""
                if host is not None and port is not None:
                    self._cached_hosts.remove((host, port))
                elif host is not None or port is not None:
                    raise ValueError('either both host and port '
                                     'or none of them are allowed')
                else:
                    self._cached_hosts.clear()

            async def _resolve_host(self,
                                    host: str, port: int,
                                    traces: Optional[List['Trace']] = None
                                    ) -> List[Dict[str, Any]]:
                if is_ip_address(host):
                    return [{'hostname': host, 'host': host, 'port': port,
                             'family': self._family, 'proto': 0, 'flags': 0}]

                if not self._use_dns_cache:

                    if traces:
                        for trace in traces:
                            await trace.send_dns_resolvehost_start(host)

                    res = (await self._resolver.resolve(
                        host, port, family=self._family))

                    if traces:
                        for trace in traces:
                            await trace.send_dns_resolvehost_end(host)

                    return res

                key = (host, port)

                if (key in self._cached_hosts) and \
                        (not self._cached_hosts.expired(key)):

                    if traces:
                        for trace in traces:
                            await trace.send_dns_cache_hit(host)

                    return self._cached_hosts.next_addrs(key)

                if key in self._throttle_dns_events:
                    if traces:
                        for trace in traces:
                            await trace.send_dns_cache_hit(host)
                    await self._throttle_dns_events[key].wait()
                else:
                    if traces:
                        for trace in traces:
                            await trace.send_dns_cache_miss(host)
                    self._throttle_dns_events[key] = \
                        EventResultOrError(self._loop)
                    try:

                        if traces:
                            for trace in traces:
                                await trace.send_dns_resolvehost_start(host)

                        addrs = await \
                            self._resolver.resolve(host, port, family=self._family)
                        if traces:
                            for trace in traces:
                                await trace.send_dns_resolvehost_end(host)

                        self._cached_hosts.add(key, addrs)
                        self._throttle_dns_events[key].set()
                    except BaseException as e:
                        # any DNS exception, independently of the implementation
                        # is set for the waiters to raise the same exception.
                        self._throttle_dns_events[key].set(exc=e)
                        raise
                    finally:
                        self._throttle_dns_events.pop(key)

                return self._cached_hosts.next_addrs(key)

            async def _create_connection(self, req: 'ClientRequest',
                                         traces: List['Trace'],
                                         timeout: ClientTimeout) -> ResponseHandler:
                """Create connection.
                Has same keyword arguments as BaseEventLoop.create_connection.
                """
                if req.proxy:
                    _, proto = await self._create_proxy_connection(
                        req, timeout)
                else:
                    _, proto = await self._create_direct_connection(
                        req, traces, timeout)

                return proto

            @staticmethod
            @functools.lru_cache(None)
            def _make_ssl_context(verified: bool) -> SSLContext:
                if verified:
                    return ssl.create_default_context()

                sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sslcontext.options |= ssl.OP_NO_SSLv2
                sslcontext.options |= ssl.OP_NO_SSLv3
                sslcontext.options |= ssl.OP_NO_COMPRESSION
                sslcontext.set_default_verify_paths()
                return sslcontext

            def _get_ssl_context(self, req: 'ClientRequest') -> Optional[SSLContext]:
                """Logic to get the correct SSL context
                0. if req.ssl is false, return None
                1. if ssl_context is specified in req, use it
                2. if _ssl_context is specified in self, use it
                3. otherwise:
                    1. if verify_ssl is not specified in req, use self.ssl_context
                       (will generate a default context according to self.verify_ssl)
                    2. if verify_ssl is True in req, generate a default SSL context
                    3. if verify_ssl is False in req, generate a SSL context that
                       won't verify
                """
                if req.is_ssl():
                    if ssl is None:  # pragma: no cover
                        raise RuntimeError('SSL is not supported.')
                    sslcontext = req.ssl
                    if isinstance(sslcontext, ssl.SSLContext):
                        return sslcontext
                    if sslcontext is not None:
                        # not verified or fingerprinted
                        return self._make_ssl_context(False)
                    sslcontext = self._ssl
                    if isinstance(sslcontext, ssl.SSLContext):
                        return sslcontext
                    if sslcontext is not None:
                        # not verified or fingerprinted
                        return self._make_ssl_context(False)
                    return self._make_ssl_context(True)

                return None

            def _get_fingerprint(self,
                                 req: 'ClientRequest') -> Optional['Fingerprint']:
                ret = req.ssl
                if isinstance(ret, Fingerprint):
                    return ret
                ret = self._ssl
                if isinstance(ret, Fingerprint):
                    return ret
                return None

            async def _wrap_create_connection(
                    self, *args: Any,
                    req: 'ClientRequest',
                    timeout: 'ClientTimeout',
                    client_error: Type[Exception] = ClientConnectorError,
                    **kwargs: Any) -> Tuple[asyncio.Transport, ResponseHandler]:
                try:
                    with CeilTimeout(timeout.sock_connect):
                        return cast(
                            Tuple[asyncio.Transport, ResponseHandler],
                            await self._loop.create_connection(*args, **kwargs))
                except cert_errors as exc:
                    raise ClientConnectorCertificateError(
                        req.connection_key, exc) from exc
                except ssl_errors as exc:
                    raise ClientConnectorSSLError(req.connection_key, exc) from exc
                except OSError as exc:
                    raise client_error(req.connection_key, exc) from exc

            async def _create_direct_connection(
                    self,
                    req: 'ClientRequest',
                    traces: List['Trace'],
                    timeout: 'ClientTimeout',
                    *,
                    client_error: Type[Exception] = ClientConnectorError
            ) -> Tuple[asyncio.Transport, ResponseHandler]:
                sslcontext = self._get_ssl_context(req)
                fingerprint = self._get_fingerprint(req)

                try:
                    # Cancelling this lookup should not cancel the underlying lookup
                    #  or else the cancel event will get broadcast to all the waiters
                    #  across all connections.
                    host = req.url.raw_host
                    assert host is not None
                    port = req.port
                    assert port is not None
                    hosts = await asyncio.shield(self._resolve_host(
                        host,
                        port,
                        traces=traces), loop=self._loop)
                except OSError as exc:
                    # in case of proxy it is not ClientProxyConnectionError
                    # it is problem of resolving proxy ip itself
                    raise ClientConnectorError(req.connection_key, exc) from exc

                last_exc = None  # type: Optional[Exception]

                for hinfo in hosts:
                    host = hinfo['host']
                    port = hinfo['port']

                    try:
                        transp, proto = await self._wrap_create_connection(
                            self._factory, host, port, timeout=timeout,
                            ssl=sslcontext, family=hinfo['family'],
                            proto=hinfo['proto'], flags=hinfo['flags'],
                            server_hostname=hinfo['hostname'] if sslcontext else None,
                            local_addr=self._local_addr,
                            req=req, client_error=client_error)
                    except ClientConnectorError as exc:
                        last_exc = exc
                        continue

                    if req.is_ssl() and fingerprint:
                        try:
                            fingerprint.check(transp)
                        except ServerFingerprintMismatch as exc:
                            transp.close()
                            if not self._cleanup_closed_disabled:
                                self._cleanup_closed_transports.append(transp)
                            last_exc = exc
                            continue

                    return transp, proto

                assert last_exc is not None
                raise last_exc

            async def _create_proxy_connection(
                    self,
                    req: 'ClientRequest',
                    timeout: 'ClientTimeout'
            ) -> Tuple[asyncio.Transport, ResponseHandler]:
                headers = {}  # type: Dict[str, str]
                if req.proxy_headers is not None:
                    headers = req.proxy_headers  # type: ignore
                headers[hdrs.HOST] = req.headers[hdrs.HOST]

                url = req.proxy
                assert url is not None
                proxy_req = ClientRequest(
                    hdrs.METH_GET, url,
                    headers=headers,
                    auth=req.proxy_auth,
                    loop=self._loop,
                    ssl=req.ssl)

                # create connection to proxy server
                transport, proto = await self._create_direct_connection(
                    proxy_req, [], timeout, client_error=ClientProxyConnectionError)

                # Many HTTP proxies has buggy keepalive support.  Let's not
                # reuse connection but close it after processing every
                # response.
                proto.force_close()

                auth = proxy_req.headers.pop(hdrs.AUTHORIZATION, None)
                if auth is not None:
                    if not req.is_ssl():
                        req.headers[hdrs.PROXY_AUTHORIZATION] = auth
                    else:
                        proxy_req.headers[hdrs.PROXY_AUTHORIZATION] = auth

                if req.is_ssl():
                    sslcontext = self._get_ssl_context(req)
                    # For HTTPS requests over HTTP proxy
                    # we must notify proxy to tunnel connection
                    # so we send CONNECT command:
                    #   CONNECT www.python.org:443 HTTP/1.1
                    #   Host: www.python.org
                    #
                    # next we must do TLS handshake and so on
                    # to do this we must wrap raw socket into secure one
                    # asyncio handles this perfectly
                    proxy_req.method = hdrs.METH_CONNECT
                    proxy_req.url = req.url
                    key = attr.evolve(req.connection_key,
                                      proxy=None,
                                      proxy_auth=None,
                                      proxy_headers_hash=None)
                    conn = Connection(self, key, proto, self._loop)
                    proxy_resp = await proxy_req.send(conn)
                    try:
                        protocol = conn._protocol
                        assert protocol is not None
                        protocol.set_response_params()
                        resp = await proxy_resp.start(conn)
                    except BaseException:
                        proxy_resp.close()
                        conn.close()
                        raise
                    else:
                        conn._protocol = None
                        conn._transport = None
                        try:
                            if resp.status != 200:
                                message = resp.reason
                                if message is None:
                                    message = RESPONSES[resp.status][0]
                                raise ClientHttpProxyError(
                                    proxy_resp.request_info,
                                    resp.history,
                                    status=resp.status,
                                    message=message,
                                    headers=resp.headers)
                            rawsock = transport.get_extra_info('socket', default=None)
                            if rawsock is None:
                                raise RuntimeError(
                                    'Transport does not expose socket instance')
                            # Duplicate the socket, so now we can close proxy transport
                            rawsock = rawsock.dup()
                        finally:
                            transport.close()

                        transport, proto = await self._wrap_create_connection(
                            self._factory, timeout=timeout,
                            ssl=sslcontext, sock=rawsock,
                            server_hostname=req.host,
                            req=req)
                    finally:
                        proxy_resp.close()

                return transport, proto

        class AioHttpDnsResolver(aiohttp.abc.AbstractResolver):
            def __init__(self):
                super().__init__()
                self.resolver, self.clear_cache = Resolver()

            async def resolve(self, host, port=0, family=socket.AF_INET):
                # Use ipv4 unless requested otherwise
                # This is consistent with the default aiohttp + aiodns AsyncResolver
                record_type = \
                    TYPES.AAAA if family == socket.AF_INET6 else \
                    TYPES.A

                try:
                    ip_addresses = await self.resolver(host, record_type)
                except DoesNotExist as does_not_exist:
                    raise OSError(0, '{} does not exist'.format(host)) from does_not_exist
                except ResolverError as resolver_error:
                    raise OSError(0, '{} failed to resolve'.format(host)) from resolver_error

                return [{
                    'hostname': host,
                    'host': str(ip_address),
                    'port': port,
                    'family': family,
                    'proto': socket.IPPROTO_TCP,
                    'flags': socket.AI_NUMERICHOST,
                } for ip_address in ip_addresses]

            async def close(self):
                self.clear_cache()

        loop = asyncio.get_event_loop()
        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(53, get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        async def handle_get(_):
            return web.Response(status=204)

        app = web.Application()
        app.add_routes([
            web.get('/page', handle_get)
        ])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8876)
        await site.start()
        self.add_async_cleanup(loop, runner.cleanup)

        async with aiohttp.ClientSession(
                connector=TCPConnector(use_dns_cache=False, resolver=AioHttpDnsResolver()),
        ) as session:
            async with await session.get('http://some-domain.com:8876/page') as result:
                self.assertEqual(result.status, 204)

            with self.assertRaisesRegex(
                    aiohttp.client_exceptions.ClientConnectorError,
                    'does not exist'):
                await session.get('http://other-domain.com:8876/page')

            with self.assertRaisesRegex(
                    aiohttp.client_exceptions.ClientConnectorError,
                    'failed to resolve'):
                await session.get('http://more-domain.com:8876/page')


class TestResolverEndToEnd(unittest.TestCase):
    """ Tests that query current real nameserver(s) for real domains
    """

    @async_test
    async def test_a_query(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        res = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertIsInstance(res[0].expires_at, float)
        self.assertTrue(loop.time() <= res[0].expires_at <= loop.time() + 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_idna_query(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        res = await resolve('michał.charemza.name', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertEqual(str(res[0]), '127.0.0.1')
        self.assertTrue(loop.time() <= res[0].expires_at <= loop.time() + 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_idna_via_cname_query(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        res = await resolve('cname-michał.charemza.name', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertEqual(str(res[0]), '127.0.0.1')
        self.assertTrue(loop.time() <= res[0].expires_at <= loop.time() + 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_query_multiple(self):
        resolve, _ = Resolver()
        res = await resolve('charemza.name', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)
        self.assertIsInstance(res[1], ipaddress.IPv4Address)
        self.assertNotEqual(res[0], res[1])

    @async_test
    async def test_txt_query(self):
        resolve, _ = Resolver()
        res = await resolve('charemza.name', TYPES.TXT)
        self.assertIn(b'google', res[0])

    @async_test
    async def test_a_query_twice_sequential(self):
        resolve, _ = Resolver()
        res_a = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res_a[0], ipaddress.IPv4Address)

        res_b = await resolve('www.google.com', TYPES.A)
        self.assertIsInstance(res_b[0], ipaddress.IPv4Address)

    @async_test
    async def test_a_query_twice_concurrent(self):
        resolve, _ = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        res_b = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        self.assertIsInstance((await res_a)[0], ipaddress.IPv4Address)
        self.assertIsInstance((await res_b)[0], ipaddress.IPv4Address)
        self.assertEqual(await res_a, await res_b)

    @async_test
    async def test_a_query_different_concurrent(self):
        resolve, _ = Resolver()
        res_a = asyncio.ensure_future(resolve('www.google.com', TYPES.A))
        res_b = asyncio.ensure_future(resolve('charemza.name', TYPES.A))
        self.assertIsInstance((await res_a)[0], ipaddress.IPv4Address)
        self.assertIsInstance((await res_b)[0], ipaddress.IPv4Address)
        self.assertNotEqual(res_a, res_b)

    @async_test
    async def test_aaaa_query(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        res = await resolve('www.google.com', TYPES.AAAA)
        self.assertIsInstance(res[0], ipaddress.IPv6Address)
        self.assertTrue(loop.time() <= res[0].expires_at <= loop.time() + 300)
        self.assertIsInstance(res, tuple)

    @async_test
    async def test_a_query_not_exists(self):
        resolve, _ = Resolver()
        with self.assertRaises(DoesNotExist):
            await resolve('doenotexist.charemza.name', TYPES.A)

    @async_test
    async def test_aaaa_query_not_exists(self):
        resolve, _ = Resolver()

        with self.assertRaises(DoesNotExist):
            await resolve('doenotexist.charemza.name', TYPES.AAAA)

    @async_test
    async def test_a_query_cname(self):
        resolve, _ = Resolver()
        res = await resolve('support.dnsimple.com', TYPES.A)
        self.assertIsInstance(res[0], ipaddress.IPv4Address)

    @async_test
    async def test_localhost_a(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        with FastForward(loop):
            res = await resolve('localhost', TYPES.A)
            self.assertIsInstance(res, tuple)
            self.assertIsInstance(res[0], ipaddress.IPv4Address)
            self.assertEqual(str(res[0]), '127.0.0.1')
            self.assertEqual(res[0].expires_at, loop.time())

    @async_test
    async def test_localhost_aaaa(self):
        loop = asyncio.get_event_loop()
        resolve, _ = Resolver()
        with FastForward(loop):
            res = await resolve('localhost', TYPES.AAAA)
            self.assertIsInstance(res, tuple)
            self.assertIsInstance(res[0], ipaddress.IPv6Address)
            self.assertEqual(str(res[0]), '::1')
            self.assertEqual(res[0].expires_at, loop.time())


def patch_open():
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

    return patched_open.stop


async def start_nameserver(port, get_response):
    loop = asyncio.get_event_loop()

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', port))

    async def server():
        client_tasks = []
        try:
            while True:
                data, addr = await recvfrom(loop, [sock], 512)
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
        server_task.cancel()
        await asyncio.sleep(0)
        sock.close()

    return stop


# recvfrom/ sendto for nonblocking sockets for use in asyncio doesn't seem to
# be part of the standard library, and not wanting the inflexibility of using
# the streams/protocol/datagram endpoint framework

async def sendto(loop, sock, data, addr):
    try:
        return sock.sendto(data, addr)
    except BlockingIOError:
        pass

    fileno = sock.fileno()
    result = asyncio.Future()

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

    loop.add_witer(fileno, write_with_writer)

    try:
        return await result
    finally:
        loop.remove_writer(fileno)


async def sendto_all(loop, sock, data, addr):
    bytes_sent = await sendto(loop, sock, data, addr)
    while bytes_sent != len(data):
        bytes_sent += await sendto(loop, sock, data[bytes_sent:], addr)
