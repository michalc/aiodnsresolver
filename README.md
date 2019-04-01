# aiodnsresolver

Asyncio Python DNS resolver: to resolve the A or AAAA record of a domain name. Only Python, with no dependencies or threads.


## Installation

```bash
pip install aiodnsresolver
```


## Usage

```python
from aiodnsresolver import Resolver, types

resolve = Resolver()
ip_addresses = await resolve('www.google.com', types.A)
```
