#!/usr/bin/env python
import os
from setuptools import setup, find_packages

setup(
    name='goldengate',
    version='2.0.0',
    description='Golden Gate is a cloud gateway',
    author='SimpleGeo',
    author_email='nerds@simplegeo.com',
    url='http://github.com/simplegeo/goldengate',
    packages=find_packages(),
    scripts=['scripts/gg-new-credentials'],
    install_requires=[
        'simplejson',
        'WebOb',
        'PyYAML',
        'IPy',
    ],
    tests_require = [
        'nose',
    ],
)
