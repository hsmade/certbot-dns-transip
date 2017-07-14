"""
Defines __version__

Set the package version here
"""
import os

VERSION_FILE_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '..',
        '.VERSION'
    )
)

LOCAL_VERSION_FILE_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        '.VERSION'
    )
)

try:
    with open(VERSION_FILE_PATH) as f:
        __version__ = f.read()
except IOError:
    with open(LOCAL_VERSION_FILE_PATH) as f:
        __version__ = f.read()
