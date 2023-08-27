import asyncio
import io
import ipaddress
import logging
import socket
import struct
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
    RESPONSE,
    TYPES,
    DnsCnameChainTooLong,
    DnsError,
    DnsRecordDoesNotExist,
    DnsSocketError,
    DnsTimeout,
    Message,
    Resolver,
    ResolverLoggerAdapter,
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, invalidate = Resolver(get_nameservers=get_nameservers)
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

            await invalidate()
            res_5 = await resolve('my.domain.quite-long.abcdefghijklm', TYPES.A)
            self.assertEqual(len(queried_names), 3)
            self.assertEqual(queried_names[2].lower(), b'my.domain.quite-long.abcdefghijklm')
            self.assertEqual(str(res_5[0]), '123.100.123.3')

    @async_test
    async def test_a_query_chained_debug_logging(self):
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        log_stream = io.StringIO()
        log_stream_handler = logging.StreamHandler(log_stream)
        log_stream_handler.setLevel('DEBUG')
        logger = logging.getLogger('aiodnsresolver')
        logger.addHandler(log_stream_handler)
        logger.setLevel('DEBUG')

        class ParentAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return '[request:%s] %s' % (self.extra['request-id'], msg), kwargs

        def get_logger_adapter_a(extra):
            parent_adapter = ParentAdapter(logging.getLogger(
                'aiodnsresolver'), {'request-id': '12345'})
            child_adapter = ResolverLoggerAdapter(parent_adapter, extra)
            return child_adapter

        def get_logger_adapter_b(extra):
            parent_adapter = ParentAdapter(logging.getLogger(
                'aiodnsresolver'), {'request-id': '12346'})
            child_adapter = ResolverLoggerAdapter(parent_adapter, extra)
            return child_adapter

        resolve, _ = Resolver(get_nameservers=get_nameservers)

        with FastForward(loop):
            await resolve(
                'my.domain', TYPES.A,
                get_logger_adapter=get_logger_adapter_a,
            )
            log = log_stream.getvalue()
            self.assertIn(
                "\n[request:12345] [dns:my.domain,A] Response from: ('127.0.0.1', 10053)\n", log)
            self.assertNotIn("\n[dns:my.domain,A] Found b'my.domain' in cache", log)

            await resolve('my.domain', TYPES.A)
            log = log_stream.getvalue()
            self.assertIn("\n[dns:my.domain,A] Found b'my.domain' in cache", log)

            await resolve(
                'my.domain', TYPES.A,
                get_logger_adapter=get_logger_adapter_a,
            )
            log = log_stream.getvalue()
            self.assertIn("\n[request:12345] [dns:my.domain,A] Found b'my.domain' in cache", log)

        log_stream = io.StringIO()
        log_stream_handler = logging.StreamHandler(log_stream)
        log_stream_handler.setLevel('DEBUG')
        logger = logging.getLogger('aiodnsresolver')
        logger.addHandler(log_stream_handler)
        logger.setLevel('DEBUG')

        resolve, _ = Resolver(get_logger_adapter=get_logger_adapter_b,
                              get_nameservers=get_nameservers)
        await resolve('my.domain', TYPES.A)
        log = log_stream.getvalue()
        self.assertIn(
            "\n[request:12346] [dns:my.domain,A] Response from: ('127.0.0.1', 10053)\n", log)

    @async_test
    async def test_a_query_truncated_logs(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            reponse_record = ResourceRecord(
                name=query.qd[0].name,
                qtype=TYPES.A,
                qclass=1,
                ttl=21,
                rdata=ipaddress.IPv4Address('123.100.123.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=1, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(reponse_record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        log_stream = io.StringIO()
        log_stream_handler = logging.StreamHandler(log_stream)
        log_stream_handler.setLevel('WARNING')
        logger = logging.getLogger('aiodnsresolver')
        logger.addHandler(log_stream_handler)
        logger.setLevel('WARNING')

        resolve, _ = Resolver(get_nameservers=get_nameservers)

        res = await resolve('my.domain', TYPES.A)
        log = log_stream.getvalue()
        self.assertIn('[dns:my.domain,A] Response truncated\n', log)
        self.assertEqual(str(res[0]), '123.100.123.1')

    @async_test
    async def test_cname_short_chain(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name
            queried_names.append(name)

            def cname_record(to):
                return ResourceRecord(
                    name=name, qtype=TYPES.CNAME, qclass=1, ttl=0, rdata=to,
                )

            def a_record(to):
                return ResourceRecord(
                    name=name, qtype=TYPES.A, qclass=1, ttl=0, rdata=to,
                )

            record = \
                cname_record(b'second') if name.lower() == b'first' else \
                cname_record(b'third') if name.lower() == b'second' else \
                a_record(ipaddress.IPv4Address('123.100.124.1').packed)
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res_1 = await resolve('first', TYPES.A)
        self.assertEqual(str(res_1[0]), '123.100.124.1')

    @async_test
    async def test_cname_long_chain(self):
        loop = asyncio.get_event_loop()
        queried_names = []

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name
            queried_names.append(name)

            record = ResourceRecord(
                name=name, qtype=TYPES.CNAME, qclass=1, ttl=0,
                rdata=('some-domain-' + str(len(queried_names))).encode(),
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record,), ns=(), ar=(),
            )
            return pack(response)

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        with self.assertRaises(DnsCnameChainTooLong):
            await resolve('first', TYPES.A)

    @async_test
    async def test_single_pointer_to_question(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1,), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)

            data_compressed = \
                data[:occurance_2] + \
                struct.pack('!H', (192 * 256) + occurance_1) + \
                data[occurance_2_end:]

            return data_compressed

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res = await resolve('some.domain', TYPES.A)
        self.assertEqual(str(res[0]), '123.100.124.1')

    @async_test
    async def test_single_pointer_to_answer(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            record_2 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.2').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1, record_2), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)
            occurance_3 = occurance_2_end + data[occurance_2_end:].index(packed_name)
            occurance_3_end = occurance_3 + len(packed_name)

            data_compressed = \
                data[:occurance_3] + \
                struct.pack('!H', (192 * 256) + occurance_2) + \
                data[occurance_3_end:]

            return data_compressed

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res = await resolve('some.domain', TYPES.A)
        self.assertEqual(str(res[0]), '123.100.124.1')
        self.assertEqual(str(res[1]), '123.100.124.2')

    @async_test
    async def test_pointer_to_pointer(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            record_2 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.2').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1, record_2), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)

            data_compressed_1 = \
                data[:occurance_2] + \
                struct.pack('!H', (192 * 256) + occurance_1) + \
                data[occurance_2_end:]

            occurance_3 = occurance_2 + 2 + data_compressed_1[occurance_2 + 2:].index(packed_name)
            occurance_3_end = occurance_3 + len(packed_name)

            data_compressed_2 = \
                data_compressed_1[:occurance_3] + \
                struct.pack('!H', (192 * 256) + occurance_2) + \
                data_compressed_1[occurance_3_end:]

            return data_compressed_2

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res = await resolve('some.domain', TYPES.A)
        self.assertEqual(str(res[0]), '123.100.124.1')
        self.assertEqual(str(res[1]), '123.100.124.2')

    @async_test
    async def test_pointer_to_self(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1,), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)

            data_compressed = \
                data[:occurance_2] + \
                struct.pack('!H', (192 * 256) + occurance_2) + \
                data[occurance_2_end:]

            return data_compressed

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        with self.assertRaises(DnsTimeout):
            await resolve('some.domain', TYPES.A)

    @async_test
    async def test_pointer_loop_two(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1,), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)

            data_compressed = \
                data[:occurance_2] + \
                struct.pack('!H', (192 * 256) + occurance_2 + 2) + \
                struct.pack('!H', (192 * 256) + occurance_2) + \
                data[occurance_2_end:]

            return data_compressed

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        with self.assertRaises(DnsTimeout):
            await resolve('some.domain', TYPES.A)

    @async_test
    async def test_pointer_loop_three(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
            query = parse(query_data)
            name = query.qd[0].name

            record_1 = ResourceRecord(
                name=query.qd[0].name, qtype=TYPES.A, qclass=1, ttl=0,
                rdata=ipaddress.IPv4Address('123.100.124.1').packed,
            )
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=(record_1,), ns=(), ar=(),
            )

            data = pack(response)
            packed_name = b''.join(
                component
                for label in name.split(b'.')
                for component in (bytes([len(label)]), label)
            ) + b'\0'

            occurance_1 = data.index(packed_name)
            occurance_1_end = occurance_1 + len(packed_name)
            occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
            occurance_2_end = occurance_2 + len(packed_name)

            data_compressed = \
                data[:occurance_2] + \
                struct.pack('!H', (192 * 256) + occurance_2 + 4) + \
                struct.pack('!H', (192 * 256) + occurance_2) + \
                struct.pack('!H', (192 * 256) + occurance_2 + 2) + \
                data[occurance_2_end:]

            return data_compressed

        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        with self.assertRaises(DnsTimeout):
            await resolve('some.domain', TYPES.A)

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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)

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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res_1 = await resolve('my.domain.that-is.fairly.long', TYPES.A)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        res_1 = await resolve('my.domain', TYPES.A)

        self.assertEqual(str(res_1[0]), '123.100.123.2')
        self.assertEqual(len(queried_names), 2)

    @async_test
    async def test_listen_then_close_local_raises_exception(self):
        loop = asyncio.get_event_loop()

        async def server():
            with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                sock.bind(('', 53))
                await recvfrom(loop, [sock], 512)
                await asyncio.sleep(0)

        self.addCleanup(patch_open())
        server_task = asyncio.ensure_future(server())
        await asyncio.sleep(0)

        async def cleanup():
            server_task.cancel()
        self.add_async_cleanup(loop, cleanup)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        # Suspect that the loopback interface "knows" if it won't be able
        # to receive packets if nothing is bound on the other end
        with self.assertRaises(DnsTimeout) as cm:
            await resolve('my.domain', TYPES.A)

        self.assertIsInstance(cm.exception.__cause__, ConnectionRefusedError)

    @async_test
    async def test_not_loopback_interface(self):
        loop = asyncio.get_event_loop()

        async def get_response(query_data):
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

        local_ip = socket.gethostbyname(socket.gethostname())

        async def get_local_nameservers(_, __):
            yield (0.5, (local_ip, 10053))

        resolve, _ = Resolver(get_nameservers=get_local_nameservers)
        res = await resolve('my.domain', TYPES.A)
        self.assertEqual(str(res[0]), '123.100.123.1')

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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
    async def test_concurrent_first_cancels_second_allows_third(self):
        # Edge case: the first task is cancelled, waking the second, but
        # before its yielded to, it gets cancelled
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)

        async def resolve_then_cancel_res_2_task():
            try:
                await resolve('my.domain', TYPES.A)
            except asyncio.CancelledError:
                res_2_task.cancel()
                raise

        res_1_task = asyncio.ensure_future(resolve_then_cancel_res_2_task())
        await asyncio.sleep(0)
        res_2_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
        res_3_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))

        res_1_task.cancel()
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        with FastForward(loop) as forward:
            resolve, _ = Resolver(get_nameservers=get_nameservers)
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

            stop_nameserver_53 = await start_nameserver(get_response_53)
            self.add_async_cleanup(loop, stop_nameserver_53)
            stop_nameserver_54 = await start_nameserver(get_response_54, port=10054)
            self.add_async_cleanup(loop, stop_nameserver_54)

            async def get_53_and_54_nameservers(_, __):
                yield (0.5, ('127.0.0.1', 10053))
                yield (0.5, ('127.0.0.1', 10054))

            resolve, _ = Resolver(get_nameservers=get_53_and_54_nameservers)

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

            stop_nameserver_53 = await start_nameserver(get_response_53)
            self.add_async_cleanup(loop, stop_nameserver_53)
            stop_nameserver_54 = await start_nameserver(get_response_54, port=10054)
            self.add_async_cleanup(loop, stop_nameserver_54)

            async def get_multiple_nameservers(_, __):
                yield (
                    0.5,
                    ('127.0.0.1', 10053),
                    ('127.0.0.1', 10054),
                )

            resolve, _ = Resolver(get_nameservers=get_multiple_nameservers)

            res = await resolve('my.domain', TYPES.A)
            self.assertEqual(str(res[0]), '123.100.123.1')
            self.assertEqual(queried_names_53[0].lower(), b'my.domain')
            self.assertEqual(queried_names_54[0].lower(), b'my.domain')

    # @async_test
    # async def test_udp_timeout_eventually_fail(self):
    #     loop = asyncio.get_event_loop()
    #     blocker = asyncio.Event()
    #     request = asyncio.Event()

    #     async def get_response(_):
    #         request.set()
    #         await blocker.wait()

    #     self.addCleanup(patch_open())
    #     stop_nameserver = await start_nameserver(get_response)
    #     self.add_async_cleanup(loop, stop_nameserver)

    #     with FastForward(loop) as forward:
    #         resolve, _ = Resolver(get_nameservers=get_nameservers)
    #         res_1_task = asyncio.ensure_future(resolve('my.domain', TYPES.A))
    #         await request.wait()
    #         await forward(2.5)

    #         with self.assertRaises(DnsTimeout):
    #             await res_1_task

    #         with self.assertRaises(DnsTimeout):
    #             await res_1_task

    @async_test
    async def test_bad_nameservers_fail(self):
        loop = asyncio.get_event_loop()

        with FastForward(loop):
            async def get_bad_nameservers(_, __):
                yield (0.5, ('300.300.300.300', 53))

            resolve, _ = Resolver(get_nameservers=get_bad_nameservers)

            with self.assertRaises(DnsSocketError) as cm:
                await resolve('my.domain', TYPES.A)

            self.assertIsInstance(cm.exception.__cause__, OSError)

    @async_test
    async def test_a_socket_error(self):
        # No nameserver started
        self.addCleanup(patch_open())

        resolve, _ = Resolver(get_nameservers=get_nameservers)
        with self.assertRaises(DnsTimeout) as cm:
            await resolve('my.domain', TYPES.A)

        self.assertIsInstance(cm.exception.__cause__, ConnectionRefusedError)

    @async_test
    async def test_bad_sock_option_raises_socket_error(self):
        def set_sock_options(sock):
            sock.setsockopt(socket.SOL_SOCKET, 1123432, 512)

        resolve, _ = Resolver(set_sock_options=set_sock_options, get_nameservers=get_nameservers)
        with self.assertRaises(DnsSocketError) as cm:
            await resolve('my.domain', TYPES.A)

        self.assertIsInstance(cm.exception.__cause__, OSError)

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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
        stop_nameserver = await start_nameserver(get_response)
        self.add_async_cleanup(loop, stop_nameserver)

        resolve, _ = Resolver(get_nameservers=get_nameservers)
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
    async def test_aiohttp_integration(self):
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
                self.resolver, self.clear_cache = Resolver(get_nameservers=get_nameservers)

            async def resolve(self, host, port=0, family=socket.AF_INET):
                # Use ipv4 unless requested otherwise
                # This is consistent with the default aiohttp + aiodns AsyncResolver
                record_type = \
                    TYPES.AAAA if family == socket.AF_INET6 else \
                    TYPES.A

                try:
                    ip_addresses = await self.resolver(host, record_type)
                except DnsRecordDoesNotExist as does_not_exist:
                    raise OSError(0, '{} does not exist'.format(host)) from does_not_exist
                except DnsError as resolver_error:
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
                await self.clear_cache()

        loop = asyncio.get_event_loop()
        self.addCleanup(patch_open())
        stop_nameserver = await start_nameserver(get_response)
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

        resolver = AioHttpDnsResolver()
        self.add_async_cleanup(loop, resolver.close)
        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(use_dns_cache=False, resolver=resolver),
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
        with self.assertRaises(DnsRecordDoesNotExist):
            await resolve('doenotexist.charemza.name', TYPES.A)

    @async_test
    async def test_aaaa_query_not_exists(self):
        resolve, _ = Resolver()

        with self.assertRaises(DnsRecordDoesNotExist):
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


async def get_nameservers(_, __):
    for _ in range(0, 5):
        yield (0.5, ('127.0.0.1', 10053))


async def start_nameserver(get_response, port=10053):
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
        finally:
            for task in client_tasks:
                task.cancel()

    async def client_task(data, addr):
        response = await get_response(data)
        # This can raise BlockingIOError, or not send all the data, but for
        # these tests, it's acceptable. Always less than 512 bytes are sent,
        # so _very_ unlikely, and if this does happen, at worse the test will
        # fail
        sock.sendto(response, addr)

    server_task = asyncio.ensure_future(server())

    async def stop():
        server_task.cancel()
        await asyncio.sleep(0)
        sock.close()

    return stop
