import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='aiodnsresolver',
    version='0.0.151',
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
    python_requires='>=3.6.4',
    test_suite='test',
    py_modules=[
        'aiodnsresolver',
    ],
)
