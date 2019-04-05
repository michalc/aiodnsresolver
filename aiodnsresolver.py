import asyncio
import collections
import contextlib
import ipaddress
import os
import secrets
import socket
import struct

QUESTION = 0
RESPONSE = 1

TYPES = collections.namedtuple('Types', [
    'A', 'CNAME', 'AAAA'
])(A=1, CNAME=5, AAAA=28)

# Field names chosen to be consistent with RFC 1035
Message = collections.namedtuple('Message', [
    'qid', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode',
    'qd', 'an', 'ns', 'ar',
])

QuestionRecord = collections.namedtuple('Record', [
    'name', 'qtype', 'qclass',
])

ResourceRecord = collections.namedtuple('Record', [
    'name', 'qtype', 'qclass', 'ttl', 'rdata',
])


def pack(message):

    def pack_string(string, btype):
        length = len(string)
        return struct.pack('B%ds' % (length), length, string)

    def pack_name(name):
        return b''.join([
            pack_string(part, 'B')
            for part in name.split(b'.')
        ]) + b'\0'

    header = struct.pack(
        '!HHHHHH',
        message.qid,
        (message.qr << 15) + (message.opcode << 11) + (message.aa << 10) + (message.tc << 9) +
        (message.rd << 8) + (message.ra << 7) + (message.z << 4) + message.rcode,
        len(message.qd),
        len(message.an),
        len(message.ns),
        len(message.ar),
    )
    records = b''.join([
        pack_name(rec.name) + struct.pack('!HH', rec.qtype, rec.qclass)
        for group in (message.qd, message.an, message.ns, message.ar)
        for rec in group
    ])
    return header + records


def parse(data):

    def byte(offset):
        return data[offset:offset + 1][0]

    def load_label(offset):
        length = byte(offset)
        return offset + length + 1, data[offset + 1:offset + 1 + length]

    def load_labels():
        nonlocal l

        followed_pointers = []
        local_cursor = l

        while True:
            if byte(local_cursor) >= 192:  # is pointer
                local_cursor = (byte(local_cursor) - 192) * 256 + byte(local_cursor + 1)
                followed_pointers.append(local_cursor)
                if len(followed_pointers) != len(set(followed_pointers)):
                    raise Exception('Pointer loop')
                if len(followed_pointers) == 1:
                    l += 2

            local_cursor, label = load_label(local_cursor)
            if not followed_pointers:
                l = local_cursor

            if label:
                yield label
            else:
                break

    def split_bits(num, *lengths):
        for length in lengths:
            high = num >> length
            yield num - (high << length)
            num = high

    def unpack(struct_format):
        nonlocal l
        dl = struct.calcsize(struct_format)
        unpacked = struct.unpack(struct_format, data[l: l + dl])
        l += dl
        return unpacked

    def parse_question_record():
        name = b'.'.join(load_labels())
        qtype, qclass = unpack('!HH')
        return QuestionRecord(name, qtype, qclass)

    def parse_resource_record():
        nonlocal l
        # The start is same as the question record
        name, qtype, qclass = parse_question_record()
        ttl, dl = unpack('!LH')
        if qtype in (TYPES.A, TYPES.AAAA):
            rdata = ipaddress.ip_address(data[l: l + dl])
            l += dl
        elif qtype == TYPES.CNAME:
            rdata = b'.'.join(load_labels())
        else:
            rdata = data[l: l + dl]
            l += dl

        return ResourceRecord(name, qtype, qclass, ttl, rdata)

    l = 0
    qid, x, qd_count, an_count, ns_count, ar_count = unpack('!HHHHHH')
    rcode, z, ra, rd, tc, aa, opcode, qr = split_bits(x, 4, 3, 1, 1, 1, 1, 4, 1)

    qd = tuple(parse_question_record() for _ in range(qd_count))
    an = tuple(parse_resource_record() for _ in range(an_count))
    ns = tuple(parse_resource_record() for _ in range(ns_count))
    ar = tuple(parse_resource_record() for _ in range(ar_count))

    return Message(qid, qr, opcode, aa, tc, rd, ra, z, rcode, qd, an, ns, ar)


async def udp_request(addr, fqdn, qtype):
    loop = asyncio.get_event_loop()

    max_attempts = 5
    for i in range(max_attempts):
        try:
            with timeout(2.0):
                qid = secrets.randbelow(65536)
                fqdn_0x20 = bytes(
                    (char | secrets.choice((32, 0))) if 65 <= char < 91 else char
                    for char in fqdn.upper()
                )
                req = Message(
                    qid=qid, qr=QUESTION, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
                    qd=(QuestionRecord(fqdn_0x20, qtype, qclass=1),), an=(), ns=(), ar=(),
                )
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

                    sock.setblocking(False)
                    await loop.sock_connect(sock, (str(addr), 53))
                    await loop.sock_sendall(sock, pack(req))

                    while True:  # We might be getting spoofed messages
                        response_data = await loop.sock_recv(sock, 512)
                        res = parse(response_data)

                        if res.qid == req.qid and res.qd == req.qd:
                            if res.rcode != 0:
                                raise Exception()
                            else:
                                return [answer for answer in res.an if answer.name == fqdn_0x20]

        except asyncio.TimeoutError:
            if i == max_attempts - 1:
                raise


def get_nameservers():
    with open('/etc/resolv.conf', 'r') as file:
        return tuple(
            ipaddress.ip_address(words_on_line[1])
            for words_on_line in [
                line.split() for line in file
                if line[0] not in ['#', ';']
            ]
            if len(words_on_line) >= 2 and words_on_line[0] == 'nameserver'
        )


def Resolver():

    async def resolve(fqdn_str, qtype):
        fqdn = fqdn_str.encode()

        with timeout(10.0):

            while True:
                nameservers = get_nameservers()
                for i in range(len(nameservers)):
                    addr = nameservers[i]
                    try:
                        answers = await memoized_udp_request(addr, fqdn, qtype)
                        break
                    except:
                        if i == len(nameservers) - 1:
                            raise

                if answers and answers[0].qtype == qtype:
                    return answers[0].rdata
                elif answers and answers[0].qtype == TYPES.CNAME:
                    fqdn = answers[0].rdata
                else:
                    raise Exception()

    def get_ttl(answers):
        return min([answer.ttl for answer in answers]) if answers else 0

    memoized_udp_request = memoize_ttl(udp_request, get_ttl)

    return resolve


def memoize_ttl(func, get_ttl):

    loop = asyncio.get_event_loop()
    cache = {}

    async def cached(*args, **kwargs):
        key = (args, tuple(kwargs.items()))

        if key in cache:
            future = cache[key]
        else:
            future = asyncio.Future()
            cache[key] = future

            try:
                start = loop.time()
                result = await func(*args, **kwargs)
            except BaseException as exception:
                del cache[key]
                future.set_exception(exception)
            else:
                future.set_result(result)
                # Err on the side of invalidation, and count TTL
                # from before we call the underlying function
                end = loop.time()
                delay = max(0, get_ttl(result) - (end - start))
                loop.call_later(delay, invalidate, key)

        return await future

    def invalidate(key):
        del cache[key]

    return cached


@contextlib.contextmanager
def timeout(max_time):

    cancelling_due_to_timeout = False
    current_task = \
        asyncio.current_task() if hasattr(asyncio, 'current_task') else \
        asyncio.Task.current_task()
    loop = \
        asyncio.get_running_loop() if hasattr(asyncio, 'get_running_loop') else \
        asyncio.get_event_loop()

    def cancel():
        nonlocal cancelling_due_to_timeout
        cancelling_due_to_timeout = True
        current_task.cancel()

    handle = loop.call_later(max_time, cancel)

    try:
        yield
    except asyncio.CancelledError:
        if cancelling_due_to_timeout:
            raise asyncio.TimeoutError()
        else:
            raise
            
    finally:
        handle.cancel()
