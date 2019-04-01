import asyncio
import collections
import contextlib
import io
import ipaddress
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
            elif self.qtype == TYPES.CNAME:
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
    def parse(cls, data):
        rqid, x, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
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


async def udp_request(fqdn, qtype, addr):
    loop = asyncio.get_event_loop()
    req = DNSMessage(qr=REQUEST, qid=secrets.randbelow(65536), o=0, aa=0, tc=0, rd=1, ra=0, r=0)
    req.qd = [Record(REQUEST, fqdn, qtype)]

    with timeout(3.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sock.setblocking(False)
            await loop.sock_connect(sock, addr)
            await loop.sock_sendall(sock, req.pack())

            while True:
                response_data = await loop.sock_recv(sock, 512)
                cres = DNSMessage.parse(response_data)
                if cres.r == 2:
                    raise Exception()
                if cres.qid == req.qid and cres.qd[0].name == req.qd[0].name:
                    return cres
        finally:
            sock.close()


async def get_remote(fqdn, qtype, nameservers):
    for addr in nameservers:
        try:
            return await udp_request(fqdn, qtype, addr)
        except:
            pass


def get_nameservers():
    with open('/etc/resolv.conf', 'r') as file:
        return [
            (words_on_line[1], 53)
            for words_on_line in [
                line.split() for line in file
            ]
            if len(words_on_line) >= 2 and words_on_line[0] == 'nameserver'
        ]


async def query_remote(fqdn, qtype):

    with timeout(5.0):
        nameservers = get_nameservers()

        while True:

            res = await get_remote(fqdn, qtype, nameservers)

            if res.an and res.an[0].qtype == qtype:
                return [answer.data for answer in res.an]
            elif res.an and res.an[0].qtype == TYPES.CNAME:
                fqdn = res.an[0].data
            else:
                raise Exception()


def Resolver():

    return memoize_concurrent(query_remote)


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
