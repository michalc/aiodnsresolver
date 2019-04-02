# aiodnsresolver [![CircleCI](https://circleci.com/gh/michalc/aiodnsresolver.svg?style=svg)](https://circleci.com/gh/michalc/aiodnsresolver) [![Test Coverage](https://api.codeclimate.com/v1/badges/8fa95ca31fe002296b9b/test_coverage)](https://codeclimate.com/github/michalc/aiodnsresolver/test_coverage)

Asyncio Python DNS resolver. Pure Python, with no dependencies other than the standard library, threads are not used, and all code is in a single module.


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
