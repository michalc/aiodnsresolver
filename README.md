# aiodnsresolver [![CircleCI](https://circleci.com/gh/michalc/aiodnsresolver.svg?style=svg)](https://circleci.com/gh/michalc/aiodnsresolver) [![Test Coverage](https://api.codeclimate.com/v1/badges/8fa95ca31fe002296b9b/test_coverage)](https://codeclimate.com/github/michalc/aiodnsresolver/test_coverage)

Asyncio Python DNS resolver. Pure Python, with no dependencies other than the standard library, threads are not used, and all code is in a single module. The nameservers to query are taken from `/etc/resolve.conf`.

Based on https://github.com/gera2ld/async_dns.


## Installation

```bash
pip install aiodnsresolver
```


## Usage

```python
from aiodnsresolver import Resolver, TYPE_A

resolve = Resolver()
ip_addresses = await resolve('www.google.com', TYPE_A)
```


## Scope

The scope of this project is deliberately restricted to operations that are used to resolve A or AAAA records: to resolve a domain name to one of its IP addresses, and have similar responsibilities to `gethostbyname`. Some limited extra behaviour is present/may be added, but great care is taken to prevent scope creep, especially to not add complexity that isn't required to resolve A or AAAA records.

- UDP queries are made, but not TCP. DNS servers must support UDP; and for a A and AAAA records, it's impossible for such a record to not fit into the maximum size of a UDP DNS response, 512 bytes. There may be other data that the DNS server would return in TCP connections, but this isn't required to resolve a domain name to a single IP address.

- CNAME records are followed transparently.

- Responses are cached, adhering to their TTL.
