from collections.abc import Mapping
from functools import partial
import sys

import pytest

from tlvdict import TLVDict

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    import mock
except ImportError:
    from unittest import mock


from collections import namedtuple

version_info = namedtuple('version_info',
                          'major,minor,micro,releaselevel,serial')

if sys.version_info[0] < 3:
    def b(s):
        return s.encode('utf8') if not isinstance(s, str) else s

    def u(s):
        return s.decode('utf8') if isinstance(s, str) else s
else:
    def b(s):
        return s.encode('utf8') if not isinstance(s, bytes) else s

    def u(s):
        return s.decode('utf8') if isinstance(s, bytes) else s

# FAKE EMV DATA
FAKE_EMV_READ = {'95': '0000000000', '57': '5104860619656847D2601101001601704095', '9B': '0000', '50': '4d4320546573742043617264', '9F07': 'FF00', '9F06': 'A0000000041010', '5F28': '0840', '5F24': '012631', '5F30': '0101', '5F25': '200531', '5F20': '4a6f6e617468616e20436f6f6b'}
FAKE_EMV_TLV = "9505000000000057125104860619656847D26011010016017040959B020000500C4D43205465737420436172649F0702FF009F0607A00000000410105F280208405F24030126315F300201015F25032005315F200D4A6F6E617468616E20436F6F6B"

def test_encode_decode():
    tlv = TLVDict.FromDict(FAKE_EMV_READ)
    assert tlv["95"] == '0000000000'
    assert tlv.getTag("95") == "0000000000"
    assert tlv.build() == FAKE_EMV_TLV

def test_decode_encode():
    tlv = TLVDict.ParseHex(FAKE_EMV_TLV)
    assert tlv["95"] == '0000000000'
    assert tlv.getTag("95") == "0000000000"
    assert tlv.build() == FAKE_EMV_TLV




