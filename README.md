# aiodnsresolver [![CircleCI](https://circleci.com/gh/michalc/aiodnsresolver.svg?style=svg)](https://circleci.com/gh/michalc/aiodnsresolver) [![Test Coverage](https://api.codeclimate.com/v1/badges/ed78fe060ed9f859fd8f/test_coverage)](https://codeclimate.com/github/michalc/aiogethostbyname/test_coverage)

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
