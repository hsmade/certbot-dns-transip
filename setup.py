#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')
version = open('.VERSION').read()

# get the requirements from the requirements.txt
requirements_file = [line.strip()
                     for line in open('requirements.txt').readlines()
                     if line.strip() and not line.startswith('#')]
requirements = requirements_file

# get the test requirements from the test_requirements.txt
test_requirements = [line.strip()
                     for line in open('requirements/testing.txt').readlines()
                     if line.strip() and not line.startswith('#')]

setup(
    name='''certbot_dns_transip''',
    version=version,
    description='''Certbot plugin to authenticate using dns TXT records via Transip API''',
    long_description=readme + '\n\n' + history,
    author='''Wim Fournier''',
    author_email='''wim@fournier.nl''',
    url='''https://github.com/hsmade/certbot_dns_transip''',
    packages=find_packages(where='.', exclude=('tests', 'hooks')),
    package_dir={'''certbot_dns_transip''':
                 '''certbot_dns_transip'''},
    include_package_data=True,
    install_requires=requirements,
    license='''Apache license 2.0''',
    zip_safe=False,
    keywords='''certbot_dns_transip''',
    entry_points={
        'certbot.plugins': [
            'dns-transip = certbot_dns_transip.dns_transip:Authenticator',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        '''License :: OSI Approved :: Apache Software License''',
        'Natural Language :: English',
        'Programming Language :: Python',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    data_files=[
        ('', [
            '.VERSION',
            'LICENSE',
            'AUTHORS.rst',
            'CONTRIBUTING.rst',
            'HISTORY.rst',
            'README.rst',
            'USAGE.rst',
        ]),
    ]
)
