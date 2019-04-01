'''
Asynchronous DNS client
'''
import asyncio
import collections
import contextlib
import io
import os
import random
import secrets
import socket
import struct
import time

REQUEST = 0
RESPONSE = 1
MAXAGE = 3600000

TYPES = collections.namedtuple('Types', [
    'NONE', 'A', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'AAAA', 'SRV', 'NAPTR', 'ANY',
])(
    NONE=0, A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, AAAA=28, SRV=33, NAPTR=35, ANY=255,
)

A_TYPES = TYPES.A, TYPES.AAAA

def _is_type(name):
    return not name.startswith('_') and name.upper() == name

_CODE_MAPPING = dict((code, name) for name, code in globals().items() if _is_type(name))


def load_name(data, offset, lower=True):
    '''Return the full name and offset from packed data.'''
    parts = []
    cursor = None
    while True:
        length = ord(data[offset : offset + 1])
        offset += 1
        if length == 0:
            if cursor is None:
                cursor = offset
            break
        elif length >= 0xc0:
            if cursor is None:
                cursor = offset + 1
            offset = (length - 0xc0) * 256 + ord(data[offset : offset + 1])
            continue
        parts.append(data[offset : offset + length])
        offset += length
    data = b'.'.join(parts).decode()
    if lower:
        data = data.lower()
    return cursor, data

def pack_string(string, btype='B'):
    '''Pack string into `{length}{data}` format.'''
    if not isinstance(string, bytes):
        string = string.encode()
    length = len(string)
    return struct.pack('%s%ds' % (btype, length), length, string)

def get_bits(num, bit_len):
    '''Get lower and higher bits breaking at bit_len from num.'''
    high = num >> bit_len
    low = num - (high << bit_len)
    return low, high

def pack_name(name, names, offset=0):
    parts = name.split('.')
    buf = io.BytesIO()
    while parts:
        subname = '.'.join(parts)
        u = names.get(subname)
        if u:
            buf.write(struct.pack('!H', 0xc000 + u))
            break
        else:
            names[subname] = buf.tell() + offset
        buf.write(pack_string(parts.pop(0)))
    else:
        buf.write(b'\0')
    return buf.getvalue()

def get_name(code, default=None):
    '''
    Get type name from code
    '''
    name = _CODE_MAPPING.get(code, default)
    if name is None:
        name = str(code)
    return name


class InternetProtocol:
    protocols = {}

    def __init__(self, name):
        self.protocol = name
        self.protocols[name] = self

    @classmethod
    def get(cls, name):
        if isinstance(name, cls):
            return name
        if isinstance(name, str):
            name = name.lower()
        return cls.protocols.get(name, UDP)

UDP = InternetProtocol('udp')

class DNSError(Exception):
    errors = {
        1: 'Format error: bad request',
        2: 'Server failure: error occurred',
        3: 'Name error: not exist',
        4: 'Not implemented: query type not supported',
        5: 'Refused: policy reasons'
    }
    def __init__(self, code, message=None):
        message = self.errors.get(code, message) or 'Unknown reply code: %d' % code
        super().__init__(message)
        self.code = code

class RData:
    '''Base class of RData'''
    rtype = -1

    @property
    def type_name(self):
        return get_name(self.rtype).lower()

class SOA_RData(RData):
    '''Start of Authority record'''
    rtype = TYPES.SOA

    def __init__(self, *k):
        (
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ) = k

    def __repr__(self):
        return '<%s: %s>' % (self.type_name, self.rname)

    @classmethod
    def load(cls, data, l):
        i, mname = load_name(data, l)
        i, rname = load_name(data, i)
        (
            serial,
            refresh,
            retry,
            expire,
            minimum,
        ) = struct.unpack('!LLLLL', data[i: i + 20])
        return i + 20, cls(mname, rname, serial, refresh, retry, expire, minimum)

    def dump(self, pack_name, offset):
        mname = pack_name(self.mname, offset + 2)
        yield mname
        yield pack_name(self.rname, offset + 2 + len(mname))
        yield struct.pack('!LLLLL', self.serial, self.refresh, self.retry, self.expire, self.minimum)


class Record:
    def __init__(self, q=RESPONSE, name='', qtype=TYPES.ANY, qclass=1, ttl=0, data=None):
        self.q = q
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        if q == RESPONSE:
            self.ttl = ttl
            self.data = data
            self.timestamp = int(time.time())

    def __repr__(self):
        if self.q == REQUEST:
            return str((self.name, get_name(self.qtype)))
        else:
            return str((self.name, get_name(self.qtype), self.data, self.ttl))

    def copy(self, **kw):
        return Record(
            q=kw.get('q', self.q),
            name=kw.get('name', self.name),
            qtype=kw.get('qtype', self.qtype),
            qclass=kw.get('qclass', self.qclass),
            ttl=kw.get('ttl', self.ttl),
            data=kw.get('data', self.data)
        )

    def update(self, other):
        if (self.name, self.qtype, self.data) == (other.name, other.qtype, other.data):
            if self.ttl and other.ttl > self.ttl:
                self.ttl = other.ttl
            return self

    def parse(self, data, l):
        l, self.name = load_name(data, l)
        self.qtype, self.qclass = struct.unpack('!HH', data[l: l + 4])
        l += 4
        if self.q == RESPONSE:
            self.timestamp = int(time.time())
            self.ttl, dl = struct.unpack('!LH', data[l: l + 6])
            l += 6
            if self.qtype == TYPES.A:
                self.data = socket.inet_ntoa(data[l: l + dl])
            elif self.qtype == TYPES.AAAA:
                self.data = socket.inet_ntop(socket.AF_INET6, data[l: l + dl])
            elif self.qtype == TYPES.SOA:
                _, self.data = SOA_RData.load(data, l)
            elif self.qtype in (TYPES.CNAME, TYPES.NS, TYPES.PTR):
                _, self.data = load_name(data, l)
            else:
                self.data = data[l: l + dl]
            l += dl
        return l

    def pack(self, names, offset=0):
        def pack_name_local(name, pack_offset):
            return pack_name(name, names, pack_offset)
        buf = io.BytesIO()
        buf.write(pack_name(self.name, names, offset))
        buf.write(struct.pack('!HH', self.qtype, self.qclass))
        if self.q == RESPONSE:
            if self.ttl < 0:
                ttl = MAXAGE
            else:
                now = int(time.time())
                self.ttl -= now - self.timestamp
                if self.ttl < 0:
                    self.ttl = 0
                self.timestamp = now
                ttl = self.ttl
            buf.write(struct.pack('!L', ttl))
            if isinstance(self.data, RData):
                data_str = b''.join(self.data.dump(pack_name_local, offset + buf.tell()))
                buf.write(pack_string(data_str, '!H'))
            elif self.qtype == TYPES.A:
                buf.write(pack_string(socket.inet_aton(self.data), '!H'))
            elif self.qtype == TYPES.AAAA:
                buf.write(pack_string(socket.inet_pton(socket.AF_INET6, self.data), '!H'))
            elif self.qtype in (TYPES.CNAME, TYPES.NS, TYPES.PTR):
                name = pack_name_local(self.data, offset + buf.tell() + 2)
                buf.write(pack_string(name, '!H'))
            else:
                buf.write(pack_string(self.data, '!H'))
        return buf.getvalue()

class DNSMessage:
    def __init__(self, qr, qid, o, aa, tc, rd, ra, r):
        self.qr = qr      # 0 for request, 1 for response
        self.qid = qid    # id for UDP package
        self.o = o        # opcode: 0 for standard query
        self.aa = aa      # Authoritative Answer
        self.tc = tc      # TrunCation
        self.rd = rd      # Recursion Desired for request
        self.ra = ra      # Recursion Available for response
        self.r = r        # rcode: 0 for success
        self.qd = []
        self.an = []
        self.ns = []
        self.ar = []

    def __getitem__(self, i):
        return self.an[i]

    def __iter__(self):
        return iter(self.an)

    def __repr__(self):
        return 'QD: %s\nAN: %s\nNS: %s\nAR: %s' % (self.qd, self.an, self.ns, self.ar)

    def pack(self):
        z = 0
        # TODO update self.tc
        buf = io.BytesIO()
        names = {}
        buf.write(struct.pack(
            '!HHHHHH',
            self.qid,
            (self.qr << 15) + (self.o << 11) + (self.aa << 10) + (self.tc << 9) + (self.rd << 8) + (self.ra << 7) + (z << 4) + self.r,
            len(self.qd),
            len(self.an),
            len(self.ns),
            len(self.ar)
        ))
        for group in self.qd, self.an, self.ns, self.ar:
            for rec in group:
                buf.write(rec.pack(names, buf.tell()))
        return buf.getvalue()

    @staticmethod
    def parse_entry(qr, data, l, n):
        res = []
        for i in range(n):
            r = Record(qr)
            l = r.parse(data, l)
            res.append(r)
        return l, res

    @classmethod
    def parse(cls, data, qid=None):
        rqid, x, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
        if qid is not None and qid != rqid:
            raise DNSError(-1, 'Message id does not match!')
        r, x = get_bits(x, 4)   # rcode: 0 for no error
        z, x = get_bits(x, 3)   # reserved
        ra, x = get_bits(x, 1)  # recursion available
        rd, x = get_bits(x, 1)  # recursion desired
        tc, x = get_bits(x, 1)  # truncation
        aa, x = get_bits(x, 1)  # authoritative answer
        o, x = get_bits(x, 4)   # opcode
        qr, x = get_bits(x, 1)  # qr: 0 for query and 1 for response
        ans = cls(qr, rqid, o, aa, tc, rd, ra, r)
        l, ans.qd = ans.parse_entry(REQUEST, data, 12, qd)
        l, ans.an = ans.parse_entry(RESPONSE, data, l, an)
        l, ans.ns = ans.parse_entry(RESPONSE, data, l, ns)
        l, ans.ar = ans.parse_entry(RESPONSE, data, l, ar)
        return ans


class InvalidHost(Exception):
    pass

class Address:
    def __init__(self, hostname, port=0, allow_domain=False):
        self.parse(hostname, port, allow_domain)

    def __eq__(self, other):
        return self.host == other.host and self.port == other.port

    def __repr__(self):
        return self.to_str()

    def parse(self, hostname, port=0, allow_domain=False):
        if isinstance(hostname, tuple):
            self.parse_tuple(hostname, allow_domain)
        elif isinstance(hostname, Address):
            self.parse_address(hostname)
        elif hostname.count(':') > 1:
            self.parse_ipv6(hostname, port)
        else:
            self.parse_ipv4_or_domain(hostname, port, allow_domain)

    def parse_tuple(self, addr, allow_domain=False):
        host, port = addr
        self.parse(host, port, allow_domain)

    def parse_address(self, addr):
        self.host, self.port, self.ip_type = addr.host, addr.port, addr.ip_type

    def parse_ipv4_or_domain(self, hostname, port=None, allow_domain=False):
        try:
            self.parse_ipv4(hostname, port)
        except InvalidHost as e:
            if not allow_domain:
                raise e
            host, _, port_s = hostname.partition(':')
            if _:
                port = int(port_s)
            self.host, self.port, self.ip_type = host, port, None

    def parse_ipv4(self, hostname, port=None):
        host, _, port_s = hostname.partition(':')
        if _:
            port = int(port_s)
        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raise InvalidHost(host)
        self.host, self.port, self.ip_type = host, port, TYPES.A

    def parse_ipv6(self, hostname, port=None):
        if hostname.startswith('['):
            i = hostname.index(']')
            host = hostname[1 : i]
            port_s = hostname[i + 1 :]
            if port_s:
                if not port_s.startswith(':'):
                    raise InvalidHost(hostname)
                port = int(port_s[1:])
        else:
            host = hostname
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            raise InvalidHost(host)
        self.host, self.port, self.ip_type = host, port, TYPES.AAAA

    def to_str(self, default_port = 0):
        if default_port is None or self.port == default_port:
            return self.host
        if self.ip_type is TYPES.A:
            return '%s:%d' % self.to_addr()
        elif self.ip_type is TYPES.AAAA:
            return '[%s]:%d' % self.to_addr()

    def to_addr(self):
        return self.host, self.port

class NameServers:
    def __init__(self, nameservers=None, default_port=53):
        self.default_port = default_port
        self.data = []
        if nameservers:
            for nameserver in nameservers:
                self.add(nameserver)

    def __bool__(self):
        return len(self.data) > 0

    def __iter__(self):
        return iter(tuple(self.data))

    def __repr__(self):
        return '<NameServers [%s]>' % ','.join(map(str, self.data))

    def get(self):
        return random.choice(self.data)

    def add(self, addr):
        self.data.append(Address(addr, self.default_port))

    def fail(self, addr):
        # TODO
        pass


async def udp_request(req, addr):
    loop = asyncio.get_event_loop()

    with timeout(3.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sock.setblocking(False)
            await loop.sock_connect(sock, addr)
            await loop.sock_sendall(sock, req.pack())

            while True:
                response_data = await loop.sock_recv(sock, 512)
                cres = DNSMessage.parse(response_data)
                if cres.qid == req.qid and cres.qd[0].name == req.qd[0].name:
                    return cres
        finally:
            sock.close()

    return result


class Resolver:
    '''
    Asynchronous DNS resolver.
    '''
    recursive = 1

    def __init__(self, protocol=UDP, timeout=3.0):
        self.futures = {}
        self.protocol = InternetProtocol.get(protocol)
        self.timeout = timeout
        self.query_remote_memoized = memoize_concurrent(self.query_remote)

    def get_nameservers(self):
        filename='/etc/resolv.conf'
        nameservers = []
        with open(filename, 'r') as file:
            for line in file:
                if line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[0] == 'nameserver':
                    nameservers.append(parts[1])
        return NameServers(nameservers)

    async def get_remote(self, nameservers, req):
        while True:
            addr = nameservers.get()
            try:
                cres = await udp_request(req, addr.to_addr())
                assert cres.r != 2
            except (asyncio.TimeoutError, AssertionError):
                nameservers.fail(addr)
            except DNSError:
                pass
            else:
                return cres

    async def query_remote(self, fqdn, qtype):
        nameservers = self.get_nameservers()

        while True:
            req = DNSMessage(qr=REQUEST, qid=secrets.randbelow(65536), o=0, aa=0, tc=0, rd=1, ra=0, r=0)
            req.qd = [Record(REQUEST, fqdn, qtype)]
            res = await self.get_remote(nameservers, req)

            if res.an and res.an[0].qtype == qtype:
                return [answer.data for answer in res.an]
            elif res.an and res.an[0].qtype == TYPES.CNAME:
                fqdn = res.an[0].data
            else:
                raise Exception()

    async def __call__(self, fqdn, qtype=TYPES.ANY):
        with timeout(self.timeout):
            return await self.query_remote_memoized(fqdn, qtype)


def memoize_concurrent(func):

    cache = {}

    async def memoized(*args, **kwargs):
        key = (args, tuple(kwargs.items()))

        try:
            future = cache[key]
        except KeyError:
            future = asyncio.Future()
            cache[key] = future

            try:
                result = await func(*args, **kwargs)
            except BaseException as exception:
                future.set_exception(exception)
            else:
                future.set_result(result)
            finally:
                del cache[key]

        return await future

    return memoized


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
