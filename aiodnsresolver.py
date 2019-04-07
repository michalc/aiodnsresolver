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
    'A', 'CNAME', 'TXT', 'AAAA'
])(A=1, CNAME=5, TXT=16, AAAA=28)

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

class ResolverError(Exception):
    pass

class TemporaryResolverError(Exception):
    pass

class DoesNotExist(ResolverError):
    pass

class IPv4AddressTTL(ipaddress.IPv4Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self._expires_at = expires_at

    def ttl(self, now):
        return max(0.0, self._expires_at - now)

class IPv6AddressTTL(ipaddress.IPv6Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self._expires_at = expires_at

    def ttl(self, now):
        return max(0.0, self._expires_at - now)

class BytesTTL(bytes):
    def __new__(cls, rdata, expires_at):
        _rdata = super().__new__(cls, rdata)
        _rdata._expires_at = expires_at
        return _rdata

    def ttl(self, now):
        return max(0.0, self._expires_at - now)

def rdata_ttl(record, ttl_start):
    expires_at = ttl_start + record.ttl
    return \
        IPv4AddressTTL(record.rdata, expires_at) if record.qtype == TYPES.A else \
        IPv6AddressTTL(record.rdata, expires_at) if record.qtype == TYPES.AAAA else \
        BytesTTL(record.rdata, expires_at)

def rdata_minimised_ttls_that_match_qtype(answers, expires_at, qtype):
    # Re-constructs the instances, but reducing their TTLs so that they expire
    # at or before expires_at, and only returns those that match the qtype
    # passed. Used when iterating through CNAMES to ensure that the the final
    # addresses have a TTL that do not go beyond any of the CNAMES used along
    # the way
    return tuple(type(rdata_ttl)(
        rdata=rdata_ttl,
        expires_at=min(expires_at, rdata_ttl._expires_at))
        for rdata_ttl, rdata_qtype in answers
        if rdata_qtype == qtype
    )


def pack(message):

    def pack_string(string):
        length = len(string)
        return struct.pack('B%ds' % (length), length, string)

    def pack_name(name):
        return b''.join([
            pack_string(part)
            for part in name.split(b'.')
        ]) + b'\0'

    def pack_resource(record):
        rdata = \
            b'.'.join(pack_name(record.rdata)) if record.qtype == TYPES.CNAME else \
            record.rdata
        ttl = struct.pack('!L', record.ttl)
        dl = struct.pack('!H', len(rdata))
        return ttl + dl + rdata

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
        for rec in message.qd
    ] + [
        pack_name(rec.name) + struct.pack('!HH', rec.qtype, rec.qclass) + pack_resource(rec)
        for group in (message.an, message.ns, message.ar)
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
        if qtype == TYPES.CNAME:
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


async def udp_request_attempt(_, addr, fqdn, qtype):
    loop = asyncio.get_event_loop()

    qid = secrets.randbelow(65536)
    fqdn_0x20 = bytes(
        (char | secrets.choice((32, 0))) if 65 <= char < 91 else char
        for char in fqdn.upper()
    )
    req = Message(
        qid=qid, qr=QUESTION, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
        qd=(QuestionRecord(fqdn_0x20, qtype, qclass=1),), an=(), ns=(), ar=(),
    )
    packed = pack(req)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_connect(sock, (str(addr), 53))
        ttl_start = loop.time()
        await loop.sock_sendall(sock, packed)

        while True:  # We might be getting spoofed messages
            response_data, _ = await recvfrom(loop, sock, 512)

            # Some initial peeking before parsing
            if len(response_data) < 12:
                continue
            qid_matches = req.qid == struct.unpack('!H', response_data[:2])[0]
            if not qid_matches:
                continue

            res = parse(response_data)
            trusted = res.qid == req.qid and res.qd == req.qd

            if not trusted:
                continue

            name_error = res.rcode == 3
            non_name_error = res.rcode and not name_error
            answers = [(rdata_ttl(answer, ttl_start), answer.qtype) for answer in res.an if answer.name == fqdn_0x20]

            if non_name_error:
                raise TemporaryResolverError()
            elif name_error or not answers:
                # a name error can be returned by some non-authoritative
                # servers on not-existing, contradicting RFC 1035
                raise DoesNotExist()
            else:
                return answers


async def recvfrom(loop, sock, max_bytes):
    # This handles cancellation better than loop.sock_recv, which seems to
    # causes later sockets on the same fileno to never receive data
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
            if not result.cancelled():
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
            if not result.cancelled():
                result.set_result((data, addr))

    read_without_reader()

    try:
        return await result
    except asyncio.CancelledError:
        loop.remove_reader(fileno)
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


def get_hosts():
    with open('/etc/hosts', 'r') as file:
        hosts = [
            (host, ipaddress.ip_address(words[0]))
            for line in file
            for (line_before_comment, _, __) in [line.partition('#')]
            for words in [line_before_comment.split()]
            for host in words[1:]
        ]
    return {
        TYPES.A: {
            host.encode(): IPv4AddressTTL(ip_address, expires_at=0)
            for host, ip_address in hosts if isinstance(ip_address, ipaddress.IPv4Address)
        },
        TYPES.AAAA: {
            host.encode(): IPv6AddressTTL(ip_address, expires_at=0)
            for host, ip_address in hosts if isinstance(ip_address, ipaddress.IPv6Address)
        }
    }


def Resolver(overall_timeout=5.0, udp_response_timeout=0.5, udp_attempts_per_server=5):

    async def resolve(fqdn_str, qtype):
        nameservers = get_nameservers()
        hosts = get_hosts()
        fqdn = BytesTTL(fqdn_str.encode(), expires_at=float('inf'))

        while True:
            if qtype in hosts and fqdn in hosts[qtype]:
                return (hosts[qtype][fqdn],)

            answers = await iterate_until_successful(
                iterator=nameservers,
                coro=memoized_udp_request, coro_args=(fqdn, qtype))

            qtype_rdata = rdata_minimised_ttls_that_match_qtype(answers, fqdn._expires_at, qtype)
            cname_rdata = rdata_minimised_ttls_that_match_qtype(answers, fqdn._expires_at, TYPES.CNAME)
            if qtype_rdata:
                return qtype_rdata
            elif cname_rdata:
                fqdn = cname_rdata[0]
            else:
                raise DoesNotExist()

    async def udp_request(addr, fqdn, qtype):
        return await iterate_until_successful(
            range(udp_attempts_per_server),
            coro=wrap_timeout(udp_response_timeout, udp_request_attempt), coro_args=(addr, fqdn, qtype))

    def get_expires_at(answers):
        return min(rdata_ttl._expires_at for rdata_ttl, _ in answers)

    memoized_udp_request = memoize_expires_at(udp_request, get_expires_at)

    return wrap_timeout(overall_timeout, resolve)


async def iterate_until_successful(iterator, coro, coro_args):
    exception = None
    for item in iterator:
        try:
            return await coro(item, *coro_args)
        except (asyncio.TimeoutError, TemporaryResolverError) as recent_exception:
            exception = recent_exception
    raise exception


def wrap_timeout(seconds, coro):

    async def wrapped(*args):
        with timeout(seconds):
            return await coro(*args)

    return wrapped


def memoize_expires_at(func, get_expires_at):
    """ Memoizing function that allows a dyamic expiry for each result

    Multiple caller for the same key wait for first call to `func` to finish,
    and will use its result.

    A queue of concurrent callers is maintained for each key. If the task
    calling the func is cancelled, the next in the queue calls `func`.
    A non-cancellation exception from `func` is propagated to all callers
    """
    loop = asyncio.get_event_loop()
    cache = {}
    waiter_queues = {}

    async def cached(*args, **kwargs):
        key = (args, tuple(kwargs.items()))

        if key in cache:
            return cache[key]

        first_call_for_key = key not in waiter_queues
        if first_call_for_key:
            waiter_queue = collections.deque()
            waiter_queues[key] = waiter_queue
        else:
            waiter_queue = waiter_queues[key]

        if not first_call_for_key:
            waiter = asyncio.Future()
            waiter_queue.append(waiter)
            await waiter

            if key in cache:
                return cache[key]

        try:
            result = await func(*args, **kwargs)

        except asyncio.CancelledError:
            # Find the next non cancelled...
            while waiter_queue and waiter_queue[0].cancelled():
                waiter_queue.popleft()

            # ... wake it up to call the func...
            if waiter_queue:
                waiter = waiter_queue.popleft()
                waiter.set_result(None)
            elif not waiter_queue:
                # Delelte the queue only if we haven't woken anything up
                del waiter_queues[key]

            # ... and propagate the cancelation
            raise

        except BaseException as exception:
            # Propagate the non-cancellation exception to all waiters
            while waiter_queue:
                waiter = waiter_queue.popleft()
                if not waiter.cancelled():
                    waiter.set_exception(exception)
            del waiter_queues[key]
            raise exception

        else:
            # Have a result, so cache it and wake up all waiters
            cache[key] = result
            while waiter_queue:
                waiter = waiter_queue.popleft()
                if not waiter.cancelled():
                    waiter.set_result(None)
            del waiter_queues[key]

            loop.call_at(get_expires_at(result), invalidate, key)
            return result

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
