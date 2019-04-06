# aiodnsresolver [![CircleCI](https://circleci.com/gh/michalc/aiodnsresolver.svg?style=svg)](https://circleci.com/gh/michalc/aiodnsresolver) [![Test Coverage](https://api.codeclimate.com/v1/badges/8fa95ca31fe002296b9b/test_coverage)](https://codeclimate.com/github/michalc/aiodnsresolver/test_coverage)

Asyncio Python DNS resolver. Pure Python, with no dependencies other than the standard library, threads are not used, and all code is in a single module. The nameservers to query are taken from `/etc/resolve.conf`.

Based on https://github.com/gera2ld/async_dns.


## Installation

```bash
pip install aiodnsresolver
```


## Usage

```python
from aiodnsresolver import Resolver, TYPES

resolve = Resolver()
ip_addresses = await resolve('www.google.com', TYPES.A)
```

Returned are tuples of subclasses of [IPv4Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address) or [IPv6Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv6Address). Both support conversion to their usual string form by passing them to `str`.


## TTL

The address objects each have an extra method, `ttl`, that returns the seconds left until the address expires.

```python
import asyncio
from aiodnsresolver import Resolver, TYPES

resolve = Resolver()
ip_addresses = await resolve('www.google.com', TYPES.A)

loop = asyncio.get_event_loop()
for ip_address in ip_address:
	print('TTL', ip_address.ttl(loop.time()))
```

This can be used in HA situations to assist failovers. The timer for TTL starts just _before_ the request to the nameserver is made.


## Example: aiohttp

```python
import asyncio
import socket

from aiodnsresolver import (
    TYPES,
    ResolverError,
    DoesNotExist,
    Resolver,
)
import aiohttp


class AioHttpDnsResolver(aiohttp.abc.AbstractResolver):
    def __init__(self):
        super().__init__()
        self.resolver = Resolver()

    async def resolve(self, host, port, family):
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
        pass


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


## Security considerations

To migitate spoofing, several techniques are used.

- Each query is given a random ID, which is checked against any response.

- Each domain name is encoded with [0x20-bit encoding](https://astrolavos.gatech.edu/articles/increased_dns_resistance.pdf), which is checked against any response.

- A new socket, and so a new random local port, is used for each query.

- Requests made for a domain while there is an in-flight query for that domain, wait for the the in-flight query to finish, and use its result.


## Scope

The scope of this project is deliberately restricted to operations that are used to resolve A or AAAA records: to resolve a domain name to its IP addresses, and have similar responsibilities to `gethostbyname`. Some limited extra behaviour is present/may be added, but great care is taken to prevent scope creep, especially to not add complexity that isn't required to resolve A or AAAA records.

- UDP queries are made, but not TCP. DNS servers must support UDP, and it's impossible for a single A and AAAA record to not fit into the maximum size of a UDP DNS response, 512 bytes. There may be other data that the DNS server would return in TCP connections, but this isn't required to resolve a domain name to a single IP address.

  It is technically possible that in the case of extremely high numbers of A or AAAA records for a domain, they would not fit in a single UDP message. However, this is extremely unlikely, and in this unlikely case, extremely unlikely to affect applications in any meaningful way.

- CNAME records are followed transparently.

- Responses are cached, adhering to their TTL.

- The resolver is a _stub_ resolver: it delegates the responsibility of recursion to the nameserver(s) it queries. In the vast majority of envisioned use cases this is acceptable, since the nameservers in `/etc/resolve.conf` will be recursive.
