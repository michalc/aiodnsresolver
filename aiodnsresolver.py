import asyncio
import collections
import contextlib
import ipaddress
import secrets
import socket
import struct

QUESTION = 0
RESPONSE = 1

TYPES = collections.namedtuple('Types', [
    'A', 'CNAME', 'TXT', 'AAAA'
])(A=1, CNAME=5, TXT=16, AAAA=28)

STRUCT_HEADER = struct.Struct('!HHHHHH')
STRUCT_TTL_RDATALEN = struct.Struct('!LH')
STRUCT_QTYPE_QCLASS = struct.Struct('!HH')

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


class TemporaryResolverError(ResolverError):
    pass


class DoesNotExist(ResolverError):
    pass


class PointerLoop(ResolverError):
    pass


class CnameChainTooLong(ResolverError):
    pass


class IPv4AddressTTL(ipaddress.IPv4Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self.expires_at = expires_at


class IPv6AddressTTL(ipaddress.IPv6Address):
    def __init__(self, rdata, expires_at):
        super().__init__(rdata)
        self.expires_at = expires_at


class BytesTTL(bytes):
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
    def byte(offset):
        return data[offset:offset + 1][0]

    def load_label(offset):
        length = byte(offset)
        return offset + length + 1, data[offset + 1:offset + 1 + length]

    def load_labels():
        nonlocal c

        followed_pointers = []
        local_cursor = c

        while True:
            while byte(local_cursor) >= 192:  # is pointer
                local_cursor = (byte(local_cursor) - 192) * 256 + byte(local_cursor + 1)
                if local_cursor in followed_pointers:
                    raise PointerLoop()
                followed_pointers.append(local_cursor)
                if len(followed_pointers) == 1:
                    c += 2

            local_cursor, label = load_label(local_cursor)
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
                if not result.done():
                    result.set_exception(exception)
            else:
                if not result.done():
                    result.set_result((data, addr))
        return _reader

    fileno_socks = tuple((sock.fileno(), sock) for sock in socks)
    result = asyncio.Future()

    for fileno, sock in fileno_socks:
        loop.add_reader(fileno, reader(sock))

    try:
        return await result
    finally:
        for fileno, _ in fileno_socks:
            loop.remove_reader(fileno)


async def get_nameservers_from_etc_resolve_conf(_):
    with open('/etc/resolv.conf', 'r') as file:
        nameservers = tuple(
            words_on_line[1]
            for words_on_line in (
                line.split() for line in file
                if line[0] not in ['#', ';']
            )
            if len(words_on_line) >= 2 and words_on_line[0] == 'nameserver'
        )
    for _ in range(5):
        for nameserver in nameservers:
            yield (0.5, (nameserver, 53))


async def get_host_from_etc_hosts(fqdn, qtype):
    with open('/etc/hosts', 'r') as file:
        hosts = tuple(
            (host, ipaddress.ip_address(words[0]))
            for line in file
            for (line_before_comment, _, __) in (line.partition('#'),)
            for words in (line_before_comment.split(),)
            for host in words[1:]
        )
    hosts = {
        TYPES.A: {
            host.encode(): IPv4AddressTTL(ip_address, expires_at=0)
            for host, ip_address in hosts if isinstance(ip_address, ipaddress.IPv4Address)
        },
        TYPES.AAAA: {
            host.encode(): IPv6AddressTTL(ip_address, expires_at=0)
            for host, ip_address in hosts if isinstance(ip_address, ipaddress.IPv6Address)
        }
    }
    try:
        return hosts[qtype][fqdn]
    except KeyError:
        return None


async def mix_case(fqdn):
    return bytes(
        (char | secrets.choice((32, 0))) if 65 <= char < 91 else char
        for char in fqdn.upper()
    )


def Resolver(
        get_host=get_host_from_etc_hosts,
        get_nameservers=get_nameservers_from_etc_resolve_conf,
        transform_fqdn=mix_case,
        max_cname_chain_length=20,
):

    loop = \
        asyncio.get_running_loop() if hasattr(asyncio, 'get_running_loop') else \
        asyncio.get_event_loop()

    cache = {}
    invalidate_callbacks = {}
    waiter_queues = {}
    woken_waiter = {}

    async def resolve(fqdn_str, qtype):
        fqdn = BytesTTL(fqdn_str.encode('idna'), expires_at=float('inf'))

        for _ in range(max_cname_chain_length):
            host = await get_host(fqdn, qtype)
            if host is not None:
                return (host,)

            cname_rdata, qtype_rdata = await memoized_udp_request(fqdn, qtype)
            min_expires_at = fqdn.expires_at  # pylint: disable=no-member
            if qtype_rdata:
                return rdata_ttl_min_expires(qtype_rdata, min_expires_at)
            fqdn = rdata_ttl_min_expires([cname_rdata[0]], min_expires_at)[0]

        raise CnameChainTooLong()

    async def memoized_udp_request(fqdn, qtype):
        """Memoized udp_request, that allows a dynamic expiry for each result

        Multiple callers for the same args will wait for first call to
        udp_request to finish, and will use its result.

        A queue of concurrent callers is maintained for the same args. If the
        task making the request is cancelled, the next in the queue will make
        it. A non-cancellation exception is propagated to all callers
        """

        key = (fqdn, qtype)

        try:
            return cache[key]
        except KeyError:
            pass

        def wake_next():
            # Find the next non cancelled...
            while waiter_queue and waiter_queue[0].cancelled():
                waiter_queue.popleft()

            # ... wake it up to call the func...
            if waiter_queue:
                waiter = waiter_queue.popleft()
                waiter.set_result((False, None))
                woken_waiter[key] = waiter
            elif not waiter_queue:
                # Delete the queue only if we haven't woken anything up
                del waiter_queues[key]

        if key not in waiter_queues:
            waiter_queue = collections.deque()
            waiter_queues[key] = waiter_queue
        else:
            waiter = asyncio.Future()
            waiter_queue = waiter_queues[key]
            waiter_queue.append(waiter)

            try:
                has_other_task_result, other_task_result = await waiter
            except asyncio.CancelledError:
                if key in woken_waiter and waiter == woken_waiter[key]:
                    wake_next()
                raise
            else:
                if has_other_task_result:
                    return other_task_result
            finally:
                if key in woken_waiter and waiter == woken_waiter[key]:
                    del woken_waiter[key]

        try:
            answers = await udp_request_namservers_until_response(fqdn, qtype)

        except asyncio.CancelledError:
            wake_next()
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
            while waiter_queue:
                waiter = waiter_queue.popleft()
                if not waiter.cancelled():
                    waiter.set_result((True, answers))
            del waiter_queues[key]

            expires_at = min(
                rdata_ttl.expires_at
                for rdata_groups in answers
                for rdata_ttl in rdata_groups
            )
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

    async def udp_request_namservers_until_response(fqdn, qtype):
        exception = ResolverError()
        async for nameserver in get_nameservers(fqdn):
            timeout, addrs = nameserver[0], nameserver[1:]
            try:
                return await timeout_udp_request_attempt(timeout, addrs, fqdn, qtype)
            except (asyncio.TimeoutError, TemporaryResolverError) as recent_exception:
                exception = recent_exception
        raise exception

    async def timeout_udp_request_attempt(timeout, addrs, fqdn, qtype):
        cancelling_due_to_timeout = False
        current_task = \
            asyncio.current_task() if hasattr(asyncio, 'current_task') else \
            asyncio.Task.current_task()

        def cancel():
            nonlocal cancelling_due_to_timeout
            cancelling_due_to_timeout = True
            current_task.cancel()

        handle = loop.call_later(timeout, cancel)

        try:
            return await udp_request_attempt(addrs, fqdn, qtype)
        except asyncio.CancelledError:
            if cancelling_due_to_timeout:
                raise asyncio.TimeoutError()
            raise

        finally:
            handle.cancel()

    async def udp_request_attempt(addrs, fqdn, qtype):
        async def req():
            qid = secrets.randbelow(65536)
            fqdn_transformed = await transform_fqdn(fqdn)
            return Message(
                qid=qid, qr=QUESTION, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
                qd=(QuestionRecord(fqdn_transformed, qtype, qclass=1),), an=(), ns=(), ar=(),
            )

        with contextlib.ExitStack() as stack:
            socks = tuple(
                stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                for addr in addrs
            )

            connections = {}
            last_exception = OSError()
            for addr_port, sock in zip(addrs, socks):
                try:
                    sock.setblocking(False)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512)
                    sock.connect(addr_port)
                except OSError as exception:
                    last_exception = exception
                else:
                    connections[addr_port] = (sock, await req())

            if not connections:
                raise last_exception

            ttl_start = loop.time()
            for (sock, req) in connections.values():
                await loop.sock_sendall(sock, pack(req))

            while connections:
                connected_socks = tuple(sock for sock, req in connections.values())
                response_data, addr_port = await recvfrom(loop, connected_socks, 512)

                try:
                    res = parse(response_data)
                except (struct.error, IndexError, PointerLoop):
                    continue

                trusted = res.qid == req.qid and res.qd == req.qd
                if not trusted:
                    continue

                del connections[addr_port]

                name_error = res.rcode == 3
                non_name_error = res.rcode and not name_error
                name_lower = req.qd[0].name.lower()
                cname_answers = tuple(
                    rdata_ttl(answer, ttl_start)
                    for answer in res.an
                    if answer.name.lower() == name_lower and answer.qtype == TYPES.CNAME
                )
                qtype_answers = tuple(
                    rdata_ttl(answer, ttl_start)
                    for answer in res.an
                    if answer.name.lower() == name_lower and answer.qtype == qtype
                )
                if non_name_error:
                    continue
                elif name_error or (not cname_answers and not qtype_answers):
                    # a name error can be returned by some non-authoritative
                    # servers on not-existing, contradicting RFC 1035
                    raise DoesNotExist()
                else:
                    return cname_answers, qtype_answers

            raise TemporaryResolverError()

    def rdata_ttl(record, ttl_start):
        expires_at = ttl_start + record.ttl
        return \
            IPv4AddressTTL(record.rdata, expires_at) if record.qtype == TYPES.A else \
            IPv6AddressTTL(record.rdata, expires_at) if record.qtype == TYPES.AAAA else \
            BytesTTL(record.rdata, expires_at)

    def rdata_ttl_min_expires(rdata_ttls, expires_at):
        return tuple(
            type(rdata_ttl)(rdata=rdata_ttl, expires_at=min(expires_at, rdata_ttl.expires_at))
            for rdata_ttl in rdata_ttls
        )

    return resolve, invalidate_all
