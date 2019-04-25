import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


def tests_require():
    with open('requirements_test.txt', 'r') as file:
        contents = file.read()
    return [
        line_before_comment.strip()
        for line in contents.splitlines()
        for (line_before_comment, _, __) in [line.partition('#')]
        if line_before_comment
    ]


setuptools.setup(
    name='aiodnsresolver',
    version='0.0.112',
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
    test_suite='test',
    tests_require=tests_require(),
    py_modules=[
        'aiodnsresolver',
    ],
)
