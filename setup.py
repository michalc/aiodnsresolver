import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='aiodnsresolver',
    version='0.0.132',
    description='Pure asyncio Python DNS resolver',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/michalc/aiodnsresolver',
    author='Gerald',
    author_email='i@gerald.top',
    license='MIT',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: Name Service (DNS)',
    ],
    keywords='async dns asyncio resolver gethostbyname getaddrinfo',
    python_requires='>=3.6.0',
    test_suite='test',
    tests_require=[
        'aiofastforward~=0.0.24',
        'aiohttp~=3.5.4',
        'async-timeout~=3.0.1',
        'attrs~=19.1.0',
        'chardet~=3.0.4',
        'idna~=2.8',
        'multidict~=4.5.2',
        'yarl~=1.3.0',
    ],
    py_modules=[
        'aiodnsresolver',
    ],
)
