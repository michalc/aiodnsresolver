# aiodnsresolver [![CircleCI](https://circleci.com/gh/michalc/aiodnsresolver.svg?style=svg)](https://circleci.com/gh/michalc/aiodnsresolver) [![Test Coverage](https://api.codeclimate.com/v1/badges/8fa95ca31fe002296b9b/test_coverage)](https://codeclimate.com/github/michalc/aiodnsresolver/test_coverage)

Asyncio Python DNS resolver. Pure Python, with no dependencies other than the standard library, threads are not used, no additional tasks are created, and all code is in a single module. The nameservers to query are taken from `/etc/resolve.conf`, and treats hosts in `/etc/hosts` as A or AAAA records with a TTL of 0.

Designed for highly concurrent/HA situations. Based on https://github.com/gera2ld/async_dns.


## Installation

```bash
pip install aiodnsresolver
```


## Usage

```python
from aiodnsresolver import Resolver, TYPES

resolve, _ = Resolver()
ip_addresses = await resolve('www.google.com', TYPES.A)
```

Returned are tuples of subclasses of [IPv4Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address) or [IPv6Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv6Address). Both support conversion to their usual string form by passing them to `str`.


## Cache

A cache is part of each `Resolver()`, expiring records automatically according to their TTL.

```python
import asyncio
from aiodnsresolver import Resolver, TYPES

resolve, clear_cache = Resolver()

# Will make a request to the nameserver(s)
ip_addresses = await resolve('www.google.com', TYPES.A)

# Will only make another request to the nameserver(s) if the ip_addresses have expired
ip_addresses = await resolve('www.google.com', TYPES.A)

clear_cache()
# Will make another request to the nameserver(s)
ip_addresses = await resolve('www.google.com', TYPES.A)
```

The cache for each record starts on the _start_ of each request, so duplicate concurrent requests for the same record are not made.


## TTL / Record expiry

The address objects each have an extra property, `expires_at`, that returns the expiry time of the address, according to the `loop.time()` clock, and the TTL of the records involved to find that address.

```python
import asyncio
from aiodnsresolver import Resolver, TYPES

resolve, _ = Resolver()
ip_addresses = await resolve('www.google.com', TYPES.A)

loop = asyncio.get_event_loop()
for ip_address in ip_address:
    print('TTL',  max(0.0, ip_address.expires_at - loop.time())
```

This can be used in HA situations to assist failovers. The timer for `expires_at` starts just _before_ the request to the nameserver is made.


## CNAMEs

CNAME records are followed transparently. The `expires_at` of IP addresses found via intermediate CNAME(s) is determined by using the minimum `expires_at` of all the records involved in determining those IP addresses.


## Custom nameservers and timeouts

It is possible to query nameservers other than those in `/etc/resolve.conf`, and for each to specify a timeout in seconds to wait for a reply before querying the next.

```python
async def get_nameservers(_, __):
    yield (0.5, ('8.8.8.8', 53))
    yield (0.5, ('1.1.1.1', 53))
    yield (1.0, ('8.8.8.8', 53))
    yield (1.0, ('1.1.1.1', 53))

resolve, _ = Resolver(get_nameservers=get_nameservers)
ip_addresses = await resolve('www.google.com', TYPES.A)
```

Parallel requests to multiple nameservers are also possible, where the first response from each set of requests is used.

```python
async def get_nameservers(_, __):
    # For any record request, udp packets are sent to both 8.8.8.8 and 1.1.1.1, waiting 0.5 seconds
    # for the first response...
    yield (0.5, ('8.8.8.8', 53), ('1.1.1.1', 53))
    # ... if no response, make another set of requests, waiting 1.0 seconds before timing out
    yield (1.0, ('8.8.8.8', 53), ('1.1.1.1', 53))

resolve, _ = Resolver(get_nameservers=get_nameservers)
ip_addresses = await resolve('www.google.com', TYPES.A)
```

This can be used as part of a HA system: if a nameserver isn't contactable, this pattern avoids waiting for its timeout before querying another nameserver.


## Custom hosts

It's possible to specify hosts without editing the `/etc/hosts` file.

```python
from aiodnsresolver import Resolver, IPv4AddressExpiresAt, TYPES

async def get_host(_, fqdn, qtype):
    hosts = {
        b'localhost': {
            TYPES.A: IPv4AddressExpiresAt('127.0.0.1', expires_at=0),
        },
        b'example.com': {
            TYPES.A: IPv4AddressExpiresAt('127.0.0.1', expires_at=0),
        },
    }
    try:
        return hosts[qtype][fqdn]
    except KeyError:
        return None

resolve, _ = Resolver(get_host=get_host)
ip_addresses = await resolve('www.google.com', TYPES.A)
```


## Exceptions

Exceptions are subclasses of `DnsError`, and are raised if a record does not exist, on socket errors, timeouts, message parsing errors, or other errors returned from the nameserver.

Specifically, if a record is determined to not exist, `DnsRecordDoesNotExist` is raised.


```python
from aiodnsresolver import Resolver, TYPES, DnsRecordDoesNotExist, DnsError

resolve, _ = Resolver()
try:
    ip_addresses = await resolve('www.google.com', TYPES.A)
except DnsRecordDoesNotExist:
    print('domain does not exist')
    raise
except DnsError as exception:
    print(type(exception))
    raise
```

If a lower-level exception caused the `DnsError`, it will be in the `__cause__` attribute of the exception.


## Security considerations

To migitate spoofing, several techniques are used.

- Each query is given a random ID, which is checked against any response.

- Each domain name is encoded with [0x20-bit encoding](https://astrolavos.gatech.edu/articles/increased_dns_resistance.pdf), which is checked against any response.

- A new socket, and so a new random local port, is used for each query.

- Requests made for a domain while there is an in-flight query for that domain, wait for the the in-flight query to finish, and use its result.

Also, to migitate the risk of evil responses/configuration

- [Pointer loops](https://nvd.nist.gov/vuln/detail/CVE-2017-2909) are detected.

- CNAME chains have a maximum length.


## Event loop, tasks, and yielding

No tasks are created, and the event loop is only yielded to during socket communication. Because fetching results from the cache involves no socket communication, this means that cached results are fetched without yielding. This introduces a small inconsistency between fetching cached and non-cached results, and so clients should be written to not depend on the presence or lack of a yield during resolution. This is a typically recommended process however: it should be expected that coroutines might yield.

The trade-off for this inconsistency is that cached results are fetched slightly faster than if resolving were to yield in all cases.

For CNAME chains, the event loop is yielded during each communication for non-cached parts of the chain.


## Scope

The scope of this project is deliberately restricted to operations that are used to resolve A or AAAA records: to resolve a domain name to its IP addresses, and have similar responsibilities to `gethostbyname`. Some limited extra behaviour is present/may be added, but great care is taken to prevent scope creep, especially to not add complexity that isn't required to resolve A or AAAA records.

- UDP queries are made, but not TCP. DNS servers must support UDP, and it's impossible for a single A and AAAA record to not fit into the maximum size of a UDP DNS response, 512 bytes. There may be other data that the DNS server would return in TCP connections, but this isn't required to resolve a domain name to a single IP address.

  It is technically possible that in the case of extremely high numbers of A or AAAA records for a domain, they would not fit in a single UDP message. However, this is extremely unlikely, and in this unlikely case, extremely unlikely to affect applications in any meaningful way.

- The resolver is a _stub_ resolver: it delegates the responsibility of recursion to the nameserver(s) it queries. In the vast majority of envisioned use cases this is acceptable, since the nameservers in `/etc/resolve.conf` will be recursive.


## Example: aiohttp

```python
import asyncio
import socket

from aiodnsresolver import (
    TYPES,
    Resolver,
    DnsError,
    DnsRecordDoesNotExist,
)
import aiohttp


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
        except DnsRecordDoesNotExist as does_not_exist:
            raise OSError(0, '{} does not exist'.format(host)) from does_not_exist
        except DnsError as dns_error:
            raise OSError(0, '{} failed to resolve'.format(host)) from dns_error

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


async def main():
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(use_dns_cache=False, resolver=AioHttpDnsResolver()),
    ) as session:
        async with await session.get('https://www.google.com/') as result:
            print(result)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()
```


## Example: tornado

```python
import asyncio
import socket

from aiodnsresolver import (
    TYPES,
    DnsError,
    DnsRecordDoesNotExist,
    Resolver,
)

import tornado.httpclient
import tornado.netutil

class AioHttpDnsResolver(tornado.netutil.Resolver):
    def initialize(self):
        self.resolver, self.clear_cache = Resolver()

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        # Use ipv4 unless ipv6 requested
        record_type, family_conn = \
            (TYPES.AAAA, socket.AF_INET6) if family == socket.AF_INET6 else \
            (TYPES.A, socket.AF_INET)

        try:
            ip_addresses = await self.resolver(host, record_type)
        except DnsRecordDoesNotExist as does_not_exist:
            raise IOError('{} does not exist'.format(host)) from does_not_exist
        except DnsError as dns_error:
            raise IOError('{} failed to resolve'.format(host)) from dns_error

        return [
            (family_conn, (str(ip_address), port))
            for ip_address in ip_addresses
        ]

    async def close(self):
        self.clear_cache()

async def main():
    tornado.netutil.Resolver.configure(AioHttpDnsResolver)
    http_client = tornado.httpclient.AsyncHTTPClient()
    response = await http_client.fetch("http://www.google.com")
    print(response.body)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()
```


## Testing strategy

Tests attempt to closly match real-world use, and assert on how input translate to output, i.e. the _public_ behaviour of the resolver. Therefore the tests avoid assumptions on implementation details.

There are however exceptions.

Many tests assume that timeouts are controlled by `asyncio.sleep`, `loop.call_later` or `loop.call_at`. This is to allow time to be fast-forwarded through cache invalidation using [aiofastforward](https://github.com/michalc/aiofastforward) without actually having to wait the corresponding time in the tests. Also, many tests assume `open` is used to access files, and patch it to allow assertions on what the code would do with different contents of `/etc/resolve.conf` or `/etc/hosts`.

While both being assumptions, they are both unlikely to change, and in the case that they are changed, this would much more likely result in tests failing incorrectly rather than passing incorrectly. Therefore these are low-risk assumptions.

A higher risk assumption is that many tests use the, otherwise private, `pack` and `parse` functions as part of the built-in DNS server that is used by the tests. These are the core functions used by the production code used to pack and parse DNS messages. While asserting that the resolver can communicate to the built-in nameserver, all the tests do is assert that `pack` and `parse` are consistent with each other: it is an assumption that other nameservers have equivalent behaviour.

To mitigate the risks that these assumptions bring, some "end to end"-style tests are included, which use whatever nameservers are in `/etc/resolve.conf`, and asserting on globally available DNS results. While not going through every possible case of input, they do validate that core behaviour is consistent with one other implementation of the protocol.
