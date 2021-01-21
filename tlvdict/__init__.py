__version_info__ = (1, 1, 0)
__version__ = ".".join(map(str, __version_info__))
ALL = ["objict"]

#!/usr/bin/env python

from collections import OrderedDict
from objict import objict
import sys
import binascii

is_py3 = sys.version_info > (3, 0)

class TLVDict(OrderedDict):
    """
    Tag-Length-Variable
    tag-length-value
    This is an "ordered" dictionary for decoding and encoding Tag-Length-Variable data
    """
    def __init__(self, *args, **kwargs):
        self.spec = kwargs.pop("spec", None)
        super(TLVDict, self).__init__(*args, **kwargs)

    def has_key(self, key):
        return key in self

    def encodeTag(self, name, value):
        # encoding is not supported in base TLVDict
        return value

    def decodeTag(self, name, value=None):
        # encoding is not supported in base TLVDict
        if value is None:
            hex_name = self.getTagHexName(name)
            return self.get(hex_name, None)
        return value

    def getTagHexName(self, name):
        # this will return a tags hex name, even if you pass in the hex name
        # some specs may decide to implement a mapping from hex names to readable names
        if self.spec and hasattr(self.spec, "getTagHexName"):
            return self.spec.getTagHexName(name)
        return name.upper()

    def hasTag(self, name):
        hex_name = self.getTagHexName(name)
        return self.has_key(hex_name)

    def removeTag(self, name):
        if type(name) is list:
            for n in name:
                self.removeTag(n)
            return
        hex_name = self.getTagHexName(name)
        if self.has_key(hex_name):
            del self[hex_name]

    def setTag(self, name, value, encode=True):
        hex_name = self.getTagHexName(name)
        if encode:
            self[hex_name] = self.encodeTag(hex_name, value)
        else:
            self[hex_name] = value

    def getTag(self, name, decode=False, ignore_false=True, default=''):
        # if name is a list then this will return new TLVDict instance
        if isinstance(name, list):
            out = self.__class__()
            for t in name:
                hex_name = self.getTagHexName(t)
                value = self.getTag(hex_name, decode, default)
                if ignore_false and not value:
                    continue
                out.setTag(hex_name, value)
            return out
        hex_name = self.getTagHexName(name)
        if decode:
            value = self.decodeTag(hex_name)
        return self.get(hex_name, default)

    def buildBytes(self, data_dict=None, skip_unknown=True, tags=None):
        out = self.build(data_dict, skip_unknown, tags)
        # print out
        out = hexToBytes(out)
        # print out
        return out

    def build(self, data_dict=None, skip_unknown=False, tags=None):
        """
        """
        if tags:
            data_dict = OrderedDict()
            for hex_tag in tags:
                if self.has_key(hex_tag):
                    data_dict[hex_tag] = self[hex_tag]

        if not data_dict:
            data_dict = self

        tlv_values = []
        for tag, value in data_dict.items():
            if not value:
                print("tag({}) has no value!".format(tag))
                continue
            # TODO dicts that are normal tags
            if isinstance(value, dict) and not isinstance(value, TLVDict):
                value = TLVDict(value)
            if isinstance(value, TLVDict):
                hex_value = value.build()
                hex_encoded = packTag(tag.upper(), hex_value)
                tlv_values.append(hex_encoded)
                continue

            if divmod(len(value), 2)[1] == 1:
                if not skip_unknown:
                    raise ValueError(
                        'Invalid value length - the length must be even')
                continue

            hex_value = value.upper()
            if hex_value is None:
                print("tag({}) has no value!".format(tag))
                continue
            hex_encoded = packTag(tag.upper(), hex_value)
            tlv_values.append(hex_encoded)

        tlv_string = ''.join(tlv_values)
        return tlv_string.upper()

    def encode(self, data_dict=None):
        if not data_dict:
            data_dict = self
        tlv_string = self.build(data_dict)
        return bytearray.fromhex(tlv_string)

    def getUnknownTags(self, tag_spec):
        unknown = []
        for key in self:
            if not tag_spec.has_key(key):
                unknown.append(key)
        return unknown

    def removeTags(self, tags):
        return self.removeUnknownTags(tags)

    def removeUnknownTags(self, tags):
        unknown = []
        for hex_tag in self:
            if hex_tag not in tags:
                unknown.append(hex_tag)

        for key in unknown:
            del self[key]
        return unknown


    @classmethod
    def ParseHex(cls, data):
        return cls.ParseBytes(bytearray.fromhex(data))

    @classmethod
    def FromHex(cls, data):
        return cls.ParseBytes(bytearray.fromhex(data))

    @classmethod
    def FromBytes(cls, data):
        return cls.ParseBytes(data)

    @classmethod
    def ParseBytes(cls, data):
        tlv = cls()
        tlv.__raw_data__ = hexify(data)
        i = 0
        while i < len(data):
            if data[i] == 0:
                i += 1
                continue
            decoded_tlv = decodeTag(data[i:])
            tag = decoded_tlv.tag
            if tag == "0":
                i += 1
                continue
            value = decoded_tlv.value
            i += decoded_tlv.total_length
            value_bytes = decoded_tlv.value_bytes
            tag_bytes = bytearray.fromhex(tag)

            if is_constructed(tag_bytes[0]):
                value = TLVDict.ParseBytes(value_bytes)

            if tlv.has_key(tag):
                value = [tlv[tag], value]
            if isString(value):
                tlv[tag] = value.upper()
            else:
                tlv[tag] = value
        return tlv

    @classmethod
    def FromDict(cls, data):
        tlv = cls()
        for key, value in data.items():
            # key = key.upper()
            if key.startswith('00'):
                key = key[2:]
            if isinstance(value, (str, bytes)):
                tlv[key] = value.upper()
            elif isinstance(value, dict):
                tlv[key] = TLVDict.FromDict(value)
            else:
                print("unsupported tag type: {}:'{}'".format(type(value), value))
        return tlv

# backwards compatability
TLV = TLVDict

def packTag(tag, value):
    """
    this takes an encoded tag value and packs it with the correct length
    """
    output = [tag]
    value_len = int(len(value) / 2)
    lenlen = getTagLengthLength(value_len)
    if lenlen == 1:
        output.append(hexify(value_len))
    else:
        lenlen -= 1
        output.append(hexify(0x80 | lenlen))
        output.append(hexify(value_len))
    output.append(value)
    return "".join(output)

def getTagLengthLength(length):
    if not length:
        return 3
    if length > 0x00FFFFFF:
        return 5
    if length > 0x0000FFFF:
        return 4
    if length > 0x000000FF:
        return 3
    if length > 0x0000007F:
        return 2
    return 1

def decodeTag(tlv_string):
    """
        klass:
            0 = universal class
                Universal classes are basic data types like integer, boolean, etc.
            1 = app class
            2 = context specific class
            3 = private class
    """
    if isString(tlv_string):
        tlv_bytes = hexToBytes(tlv_string)
    else:
        tlv_bytes = tlv_string
    tag = [tlv_bytes[0]]
    tag_length = 0
    tag_value = None
    is_cons = getBit(tlv_bytes[0], 6)
    # turning b8 b7 into simple int
    klass = (tlv_bytes[0] & 192) >> 6
    tag_type = 0
    if klass == 0:
        tag_type = tlv_bytes[0] & 31
    pos = 1

    # short vs long tag names
    # long names bits 1-5 are all 1 (0x1F == 00011111)
    if (tlv_bytes[0] & 31) == 31:
        tag.append(tlv_bytes[pos])
        # if bit 8 is 1 then we have another tag after to read
        while getBit(tlv_bytes[pos], 8):
            pos += 1
            tag.append(tlv_bytes[pos])
        pos += 1

    # decode the length
    # if b8 == 0 it is single byte length
    if not getBit(tlv_bytes[pos], 8):
        tag_length = tlv_bytes[pos]
    else:
        num_bytes = tlv_bytes[pos] & 127
        epos = pos + num_bytes
        if epos > len(tlv_bytes):
            # this is typically a parsing error?
            tag_length = 0
        elif num_bytes == 1:
            tag_length = tlv_bytes[epos]
        else:
            while epos != pos:
                tag_length += tlv_bytes[epos] << 8
                epos = epos - 1
        pos = epos
    pos += 1
    epos = pos + tag_length
    value_bytes = tlv_bytes[pos:epos]
    tag_value = bytesToHex(value_bytes)
    tag_hex = bytesToHex(tag)
    if len(tag_hex) == 1:
        tag_hex = tag_hex.rjust(2, '0')
    return objict(
        tag=tag_hex,
        length=tag_length,
        value=tag_value,
        total_length=epos,
        is_constructed=is_cons,
        klass=klass,
        type=tag_type,
        value_bytes=value_bytes,
    )

def is_two_byte(val):
    """ A tag is at least two bytes long if the least significant
        5 bits of the first byte are set. """
    return val & 0b00011111 == 0b00011111


def is_continuation(val):
    """ Any subsequent byte is a continuation byte if the MSB is set. """
    return val & 0b10000000 == 0b10000000


def is_constructed(val):
    """ Check if a tag represents a "constructed" value, i.e. another TLV """
    return val & 0b00100000 == 0b00100000


def hexToBytes(hex_value):
    if not isString(hex_value):
        # print("not hex: {}:{}".format(hex_value, type(hex_value)))
        pass
    return bytearray.fromhex(hex_value)

def isString(value):
    if is_py3:
        return isinstance(value, str) or isinstance(value, bytes)
    return isinstance(value, basestring)

def getBit(byteval, idx):
    idx -= 1
    return (byteval & (1 << idx)) != 0


def setBit(byteval, idx, on=True):
    if not on:
        return clearBit(byteval, idx)
    idx -= 1
    mask = 1 << idx
    return byteval | mask


def clearBit(byteval, idx):
    idx -= 1
    mask = ~(1 << idx)
    return byteval & mask


def bytesToHex(data):
    if type(data) is list or isinstance(data, bytes):
        data = bytearray(data)
    if is_py3:
        return str(binascii.hexlify(data), "utf-8")
    return binascii.hexlify(data).upper()


def isHex(hex_value):
    if (len(hex_value) % 2) == 0:
        try:
            int(hex_value, 16)
            return True
        except:
            pass
    return False


def intToHex(value, size=0):
    if value < 0:
        raise ValueError("Invalid value to hexify - must be positive")

    result = hex(int(value)).replace("0x", "").upper()
    if divmod(len(result), 2)[1] == 1:
        # Padding
        result = "0{}".format(result)
    if size:
        return result.rjust(size, "0")
    return result


def hexToInt(hex_value):
    return int(hex_value, 16)


def bytesToInt(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result


def strToHex(value):
    if is_py3:
        return bytes.hex(value.encode("utf-8")).upper()
    return value.encode("hex").upper()


def hexToStr(hex_value):
    if is_py3:
        return str(bytes.fromhex(hex_value), "utf-8")
    return hex_value.decode("hex")


def hexify(value):
    """
    Convert integer to hex string representation, e.g. 12 to '0C'
    """
    if type(value) is list:
        hl = []
        for i in value:
            hl.append(hexify(i))
        return "".join(hl)

    if isinstance(value, int):
        return intToHex(value)
    elif isinstance(value, bytearray):
        return bytesToHex(value)
    elif isString(value):
        return strToHex(value)
    return value

