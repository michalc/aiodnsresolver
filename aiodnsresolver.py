from asyncio import (
    CancelledError,
    Future,
)

try:
    from asyncio import get_running_loop
except ImportError:
    from asyncio import get_event_loop as get_running_loop

try:
    from asyncio import current_task
except ImportError:
    from asyncio import Task
    current_task = Task.current_task
    del Task

from collections import (
    deque,
    namedtuple,
)
from contextlib import (
    ExitStack,
)
from ipaddress import (
    IPv4Address,
    IPv6Address,
    ip_address,
)
from secrets import (
    choice,
    randbelow,
)
from socket import (
    AF_INET,
    SO_RCVBUF,
    SO_SNDBUF,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)
from struct import (
    Struct,
    error as struct_error,
)
from weakref import (
    WeakValueDictionary,
)

QUESTION = 0
RESPONSE = 1

TYPES = namedtuple('Types', [
    'A', 'CNAME', 'TXT', 'AAAA'
])(A=1, CNAME=5, TXT=16, AAAA=28)

STRUCT_HEADER = Struct('!HHHHHH')
STRUCT_TTL_RDATALEN = Struct('!LH')
STRUCT_QTYPE_QCLASS = Struct('!HH')

# Field names chosen to be consistent with RFC 1035
Message = namedtuple('Message', [
    'qid', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode',
    'qd', 'an', 'ns', 'ar',
])

QuestionRecord = namedtuple('Record', [
    'name', 'qtype', 'qclass',
])

ResourceRecord = namedtuple('Record', [
    'name', 'qtype', 'qclass', 'ttl', 'rdata',
])


class DnsError(Exception):
    pass


class DnsCnameChainTooLong(DnsError):
    pass


class DnsRecordDoesNotExist(DnsError):
    pass


class DnsPointerLoop(DnsError):
    pass


class DnsResponseCode(DnsError):
    pass


class DnsSocketError(DnsError):
    pass


class DnsTimeout(DnsError):
    pass


class IPv4AddressExpiresAt(IPv4Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self.expires_at = expires_at


class IPv6AddressExpiresAt(IPv6Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self.expires_at = expires_at


class BytesExpiresAt(bytes):
    def __new__(cls, rdata, expires_at):
        _rdata = super().__new__(cls, rdata)
        _rdata.expires_at = expires_at
        return _rdata


def pack(message):
    def pack_name(name):
        return b''.join(
            bytes((len(part),)) + part
            for part in name.split(b'.')
        ) + b'\0'

    def pack_resource(record):
        rdata = \
            pack_name(record.rdata) if record.qtype == TYPES.CNAME else \
            record.rdata
        return STRUCT_TTL_RDATALEN.pack(record.ttl, len(rdata)) + rdata

    header = STRUCT_HEADER.pack(
        message.qid,
        (message.qr << 15) + (message.opcode << 11) + (message.aa << 10) + (message.tc << 9) +
        (message.rd << 8) + (message.ra << 7) + (message.z << 4) + message.rcode,
        len(message.qd),
        len(message.an),
        len(message.ns),
        len(message.ar),
    )
    records = b''.join(tuple(
        pack_name(rec.name) + STRUCT_QTYPE_QCLASS.pack(rec.qtype, rec.qclass)
        for rec in message.qd
    ) + tuple(
        pack_name(rec.name) + STRUCT_QTYPE_QCLASS.pack(rec.qtype, rec.qclass) + pack_resource(rec)
        for group in (message.an, message.ns, message.ar)
        for rec in group
    ))
    return header + records


def parse(data):
    def load_labels():
        nonlocal c

        followed_pointers = ()
        local_cursor = c

        while True:
            while data[local_cursor] >= 192:  # is pointer
                local_cursor = (data[local_cursor] - 192) * 256 + data[local_cursor + 1]
                if not followed_pointers:
                    c += 2
                if local_cursor in followed_pointers:
                    raise DnsPointerLoop()
                followed_pointers += (local_cursor,)

            label_length = data[local_cursor]
            label = data[local_cursor + 1:local_cursor + 1 + label_length]
            local_cursor = local_cursor + 1 + label_length

            if not followed_pointers:
                c = local_cursor

            if label:
                yield label
            else:
                break

    def split_bits(num, *lengths):
        for length in lengths:
            high = num >> length
            yield num - (high << length)
            num = high

    def unpack(struct_obj):
        nonlocal c
        unpacked = struct_obj.unpack_from(data, c)
        c += struct_obj.size
        return unpacked

    def parse_question_record():
        name = b'.'.join(load_labels())
        qtype, qclass = unpack(STRUCT_QTYPE_QCLASS)
        return QuestionRecord(name, qtype, qclass)

    def parse_resource_record():
        nonlocal c
        # The start is same as the question record
        name, qtype, qclass = parse_question_record()
        ttl, dc = unpack(STRUCT_TTL_RDATALEN)
        if qtype == TYPES.CNAME:
            rdata = b'.'.join(load_labels())
        else:
            rdata = data[c: c + dc]
            c += dc

        return ResourceRecord(name, qtype, qclass, ttl, rdata)

    c = 0
    qid, x, qd_count, an_count, ns_count, ar_count = unpack(STRUCT_HEADER)
    rcode, z, ra, rd, tc, aa, opcode, qr = split_bits(x, 4, 3, 1, 1, 1, 1, 4, 1)

    qd = tuple(parse_question_record() for _ in range(qd_count))
    an = tuple(parse_resource_record() for _ in range(an_count))
    ns = tuple(parse_resource_record() for _ in range(ns_count))
    ar = tuple(parse_resource_record() for _ in range(ar_count))

    return Message(qid, qr, opcode, aa, tc, rd, ra, z, rcode, qd, an, ns, ar)


async def recvfrom(loop, socks, max_bytes):
    for sock in socks:
        try:
            return sock.recvfrom(max_bytes)
        except BlockingIOError:
            pass

    def reader(sock):
        def _reader():
            try:
                (data, addr) = sock.recvfrom(max_bytes)
            except BlockingIOError:
                pass
            except BaseException as exception:
                remove_readers()
                if not result.done():
                    result.set_exception(exception)
            else:
                remove_readers()
                if not result.done():
                    result.set_result((data, addr))
        return _reader

    fileno_socks = tuple((sock.fileno(), sock) for sock in socks)
    result = Future()

    for fileno, sock in fileno_socks:
        loop.add_reader(fileno, reader(sock))

    def remove_readers():
        for fileno, _ in fileno_socks:
            loop.remove_reader(fileno)

    try:
        return await result
    finally:
        remove_readers()


def parse_resolve_conf():
    with open('/etc/resolv.conf', 'r') as file:
        lines = tuple(file)
    return tuple(
        words_on_line[1]
        for words_on_line in (
            line.split() for line in lines
            if line[0] not in ('#', ';')
        )
        if len(words_on_line) >= 2 and words_on_line[0] == 'nameserver'
    )


async def get_nameservers_default(nameservers, _):
    for _ in range(5):
        for nameserver in nameservers:
            yield (0.5, (nameserver, 53))


def parse_etc_hosts():
    with open('/etc/hosts', 'r') as file:
        lines = tuple(file)
    hosts = tuple(
        (host.encode(), ip_address(words[0]))
        for line in lines
        for (line_before_comment, _, __) in (line.partition('#'),)
        for words in (line_before_comment.split(),)
        for host in words[1:]
    )
    return {
        TYPES.A: {
            host: IPv4AddressExpiresAt(address, expires_at=0)
            for host, address in hosts if isinstance(address, IPv4Address)
        },
        TYPES.AAAA: {
            host: IPv6AddressExpiresAt(address, expires_at=0)
            for host, address in hosts if isinstance(address, IPv6Address)
        }
    }


async def get_host_default(hosts, fqdn, qtype):
    try:
        return hosts[qtype][fqdn]
    except KeyError:
        return None


async def mix_case(fqdn):
    return bytes(
        (char | choice((32, 0))) if 65 <= char < 91 else char
        for char in fqdn.upper()
    )


def set_sock_options_default(sock):
    sock.setsockopt(SOL_SOCKET, SO_SNDBUF, 512)
    sock.setsockopt(SOL_SOCKET, SO_RCVBUF, 512)


def Resolver(
        get_host=get_host_default,
        get_nameservers=get_nameservers_default,
        set_sock_options=set_sock_options_default,
        transform_fqdn=mix_case,
        max_cname_chain_length=20,
):

    loop = get_running_loop()

    cache = {}
    invalidate_callbacks = {}
    in_progress = WeakValueDictionary()
    parsed_etc_hosts = parse_etc_hosts()
    parsed_resolve_conf = parse_resolve_conf()

    async def resolve(fqdn_str, qtype):
        fqdn = BytesExpiresAt(fqdn_str.encode('idna'), expires_at=float('inf'))

        for _ in range(max_cname_chain_length):
            host = await get_host(parsed_etc_hosts, fqdn, qtype)
            if host is not None:
                return (host,)

            cname_rdata, qtype_rdata = await request_memoized(fqdn, qtype)
            min_expires_at = fqdn.expires_at  # pylint: disable=no-member
            if qtype_rdata:
                return rdata_expires_at_min(qtype_rdata, min_expires_at)
            fqdn = rdata_expires_at_min([cname_rdata[0]], min_expires_at)[0]

        raise DnsCnameChainTooLong()

    async def request_memoized(fqdn, qtype):
        key = (fqdn, qtype)

        try:
            return cache[key]
        except KeyError:
            pass

        try:
            memoized_mutex = in_progress[key]
        except KeyError:
            memoized_mutex = MemoizedMutex(request_and_cache, fqdn, qtype)
            in_progress[key] = memoized_mutex

        return await memoized_mutex()

    async def request_and_cache(fqdn, qtype):
        answers = await request_until_response(fqdn, qtype)

        expires_at = min(
            rdata_ttl.expires_at
            for rdata_groups in answers
            for rdata_ttl in rdata_groups
        )
        key = (fqdn, qtype)
        invalidate_callbacks[key] = loop.call_at(expires_at, invalidate, key)
        cache[key] = answers
        return answers

    def invalidate(key):
        del cache[key]
        invalidate_callbacks.pop(key).cancel()

    def invalidate_all():
        for callback in invalidate_callbacks.values():
            callback.cancel()
        invalidate_callbacks.clear()
        cache.clear()

    async def request_until_response(fqdn, qtype):
        exception = DnsError()
        async for nameserver in get_nameservers(parsed_resolve_conf, fqdn):
            timeout, addrs = nameserver[0], nameserver[1:]
            try:
                return await request_with_timeout(timeout, addrs, fqdn, qtype)
            except DnsRecordDoesNotExist:
                raise
            except DnsError as recent_exception:
                exception = recent_exception

        raise exception

    async def request_with_timeout(timeout, addrs, fqdn, qtype):
        cancelling_due_to_timeout = False
        task = current_task()

        def cancel():
            nonlocal cancelling_due_to_timeout
            cancelling_due_to_timeout = True
            task.cancel()

        handle = loop.call_later(timeout, cancel)

        last_exception = None

        def set_timeout_cause(exception):
            nonlocal last_exception
            last_exception = exception

        try:
            return await request(addrs, fqdn, qtype, set_timeout_cause)
        except CancelledError:
            if cancelling_due_to_timeout:
                raise DnsTimeout() from last_exception
            raise

        finally:
            handle.cancel()

    async def request(addrs, fqdn, qtype, set_timeout_cause):
        async def req():
            qid = randbelow(65536)
            fqdn_transformed = await transform_fqdn(fqdn)
            return Message(
                qid=qid, qr=QUESTION, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
                qd=(QuestionRecord(fqdn_transformed, qtype, qclass=1),), an=(), ns=(), ar=(),
            )

        with ExitStack() as stack:
            socks = tuple(
                stack.enter_context(socket(AF_INET, SOCK_DGRAM))
                for addr in addrs
            )

            connections = {}
            last_exception = OSError()
            for addr_port, sock in zip(addrs, socks):
                try:
                    sock.setblocking(False)
                    set_sock_options(sock)
                    sock.connect(addr_port)
                except OSError as exception:
                    last_exception = exception
                    set_timeout_cause(exception)
                else:
                    connections[addr_port] = (sock, await req())

            if not connections:
                raise DnsSocketError() from last_exception

            ttl_start = loop.time()
            for (sock, req) in connections.values():
                await loop.sock_sendall(sock, pack(req))

            last_exception = DnsError()
            while connections:
                connected_socks = tuple(sock for sock, req in connections.values())
                try:
                    response_data, addr_port = await recvfrom(loop, connected_socks, 512)
                except OSError as exception:
                    last_exception = exception
                    set_timeout_cause(exception)
                    continue

                try:
                    res = parse(response_data)
                except (struct_error, IndexError, DnsPointerLoop) as exception:
                    last_exception = exception
                    set_timeout_cause(exception)
                    continue

                trusted = res.qid == req.qid and res.qd == req.qd
                if not trusted:
                    continue

                del connections[addr_port]

                name_error = res.rcode == 3
                non_name_error = res.rcode and not name_error
                name_lower = req.qd[0].name.lower()
                cname_answers = tuple(
                    rdata_expires_at(answer, ttl_start + answer.ttl)
                    for answer in res.an
                    if answer.name.lower() == name_lower and answer.qtype == TYPES.CNAME
                )
                qtype_answers = tuple(
                    rdata_expires_at(answer, ttl_start + answer.ttl)
                    for answer in res.an
                    if answer.name.lower() == name_lower and answer.qtype == qtype
                )
                if non_name_error:
                    last_exception = DnsResponseCode(res.rcode)
                    set_timeout_cause(last_exception)
                elif name_error or (not cname_answers and not qtype_answers):
                    # a name error can be returned by some non-authoritative
                    # servers on not-existing, contradicting RFC 1035
                    raise DnsRecordDoesNotExist()
                else:
                    return cname_answers, qtype_answers

            if isinstance(last_exception, DnsError):
                raise last_exception
            raise DnsError() from last_exception

    def rdata_expires_at(record, expires_at):
        return \
            IPv4AddressExpiresAt(record.rdata, expires_at) if record.qtype == TYPES.A else \
            IPv6AddressExpiresAt(record.rdata, expires_at) if record.qtype == TYPES.AAAA else \
            BytesExpiresAt(record.rdata, expires_at)

    def rdata_expires_at_min(rdatas, expires_at):
        return tuple(
            type(rdata)(rdata=rdata, expires_at=min(expires_at, rdata.expires_at))
            for rdata in rdatas
        )

    return resolve, invalidate_all


def MemoizedMutex(func, *args):

    waiters = deque()
    acquired = False
    has_result = False
    result = ()

    def maybe_acquire():
        nonlocal acquired

        while waiters:

            if waiters[0].cancelled():
                waiters.popleft()

            elif not acquired:
                waiter = waiters.popleft()
                acquired = True
                waiter.set_result(None)

            else:
                break

    async def runner():
        nonlocal acquired, has_result, result

        waiter = Future()
        waiters.append(waiter)
        maybe_acquire()

        try:
            await waiter
        except CancelledError:
            if waiter.done() and not waiter.cancelled():
                acquired = False
                maybe_acquire()
            raise

        if has_result:
            return result

        try:
            result = await func(*args)
        except CancelledError:
            acquired = False
            maybe_acquire()
            raise
        except BaseException as exception:
            acquired = False
            while waiters:
                waiter = waiters.popleft()
                if not waiter.cancelled():
                    waiter.set_exception(exception)
            raise
        else:
            acquired = False
            has_result = True
            while waiters:
                waiter = waiters.popleft()
                if not waiter.cancelled():
                    waiter.set_result(None)
            return result

    return runner
