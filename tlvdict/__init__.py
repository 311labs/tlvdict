from collections import OrderedDict
from objict import objict
import sys

__version_info__ = (1, 2, 0)
__version__ = ".".join(map(str, __version_info__))
ALL = ["tlvdict"]

is_py3 = sys.version_info > (3, 0)


def parse(data):
    # attempts to parse data into a TLVDict
    return TLVDict.Parse(data)


def encode(data):
    tlv = TLVDict.FromDict(data)
    return tlv.toHex()


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
        # decoding is not supported in base TLVDict
        if value is None:
            hex_name = self.getTagHexName(name)
            return self.get(hex_name, None)
        return value

    def getTagName(self, name):
        return EMV_TAGS_TO_NAMES.get(name, name)

    def getTagHexName(self, name):
        # this will return a tags hex name, even if you pass in the hex name
        # some specs may decide to implement a mapping from hex names to readable names
        if self.spec and hasattr(self.spec, "getTagHexName"):
            return self.spec.getTagHexName(name)
        if name in EMV_NAMES_TO_TAGS:
            return EMV_NAMES_TO_TAGS[name]
        return name.upper()

    def hasTag(self, name):
        hex_name = self.getTagHexName(name)
        return hex_name in self

    def removeTag(self, name):
        if type(name) is list:
            for n in name:
                self.removeTag(n)
            return
        hex_name = self.getTagHexName(name)
        if hex_name in self:
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
                if hex_tag in self:
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

    def toHex(self):
        return self.build(self)

    def toDict(self, readable=True):
        out = objict()
        for key, value in self.items():
            out[self.getTagName(key)] = value
        return out

    def getUnknownTags(self, tag_spec):
        unknown = []
        for key in self:
            if key not in tag_spec:
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
    def Parse(cls, data):
        if isinstance(data, str):
            return cls.ParseBytes(bytearray.fromhex(data))
        elif isinstance(data, bytes):
            return cls.ParseBytes(data)
        elif isinstance(data, dict):
            return cls.FromDict(data)
        raise ValueError("invalid format for parsing: {}".format(type(data)))

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

            if tag in tlv:
                value = [tlv[tag], value]
            if isString(value):
                tlv[tag] = value.upper()
            else:
                tlv[tag] = value
        return tlv

    @classmethod
    def FromDict(cls, data):
        if not isinstance(data, dict):
            return cls.Parse(data)
        tlv = cls()
        for key, value in data.items():
            # key = key.upper()
            if key.startswith('00'):
                key = key[2:]
            if key.lower() in EMV_NAMES_TO_TAGS:
                key = EMV_NAMES_TO_TAGS[key]
            if isinstance(value, (str, bytes)):
                tlv[key] = value.upper()
            elif isinstance(value, dict):
                tlv[key] = TLVDict.FromDict(value)
            elif value is None:
                # we remove tags that have no value
                continue
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


def toBytes(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    elif isinstance(value, bytearray):
        value = bytes(value)
    elif isinstance(value, list):
        value = bytes(bytearray(value))
    return value


def toHex(value):
    return toBytes(value).hex().upper()


def bytesToHex(data):
    return toHex(data)


def isHex(hex_value):
    if (len(hex_value) % 2) == 0:
        try:
            int(hex_value, 16)
            return True
        except Exception:
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


EMV_TAGS_TO_NAMES = {
    "06": "oid",
    "42": "iin",
    "46": "pre_issuing_data",
    "4F": "adf_name",
    "50": "app_label",
    "56": "track1",
    "57": "track2",
    "5A": "pan",
    "5C": "tag_list",
    "5F20": "name",
    "5F24": "app_expires",
    "5F25": "app_effective",
    "5F28": "app_country",
    "5F2A": "transaction_country",
    "5F2D": "langs",
    "5F30": "service_code",
    "5F34": "app_pan_seq",
    "5F36": "currency_exponent",
    "5F50": "issuer_url",
    "5F53": "iban",
    "5F54": "bic",
    "5F55": "app_country_a2",
    "5F56": "app_country_a3",
    "5F57": "card_type",
    "60": "template",
    "61": "app_record",
    "63": "wrapper",
    "64": "fmd",
    "65": "cardholder_data",
    "6F": "fci",
    "70": "record",
    "71": "ist1",
    "72": "ist2",
    "73": "ddt",
    "77": "rmtf2",
    "80": "rmtf1",
    "81": "amount_authorized_binary",
    "82": "aip",
    "84": "df",
    "87": "app_priority",
    "88": "sfi",
    "89": "auth_code",
    "8A": "auth_resp_code",
    "8C": "cdol1",
    "8D": "cdol2",
    "8E": "cvm_list",
    "8F": "issuer_pub_key_index",
    "90": "issuer_pub_key_cert",
    "91": "issuer_auth_data",
    "92": "issuer_pub_key_remainder",
    "93": "signed_app_data",
    "94": "afl",
    "95": "tvr",
    "97": "tdol",
    "98": "tc_hash",
    "99": "transaction_pin",
    "9A": "transaction_date",
    "9B": "tsi",
    "9C": "transaction_type",
    "9D": "ddf",
    "9F01": "acquirer_id",
    "9F02": "amount_authorized",
    "9F03": "amount_other",
    "9F04": "amount_other_binary",
    "9F06": "terminal_aid",
    "9F07": "auc",
    "9F08": "icc_app_version",
    "9F09": "terminal_app_version",
    "9F0B": "name_ext",
    "9F0D": "iac_default",
    "9F0E": "iac_denial",
    "9F0F": "iac_online",
    "9F10": "iad",
    "9F11": "icti",
    "9F12": "app_preferred_name",
    "9F13": "last_online_atc",
    "9F15": "mcc",
    "9F16": "merchant_id",
    "9F17": "pin_tries_remaining",
    "9F1A": "term_country_code",
    "9F1B": "terminal_floor_limit",
    "9F1C": "tid",
    "9F1D": "terminal_risk_management",
    "9F1E": "ifd_serial_number",
    "9F1F": "track1_disc",
    "9F20": "track2_disc",
    "9F21": "transaction_time",
    "9F24": "par",
    "9F26": "cryptogram",
    "9F27": "cid",
    "9F2D": "icc_pin_pk",
    "9F2E": "icc_pin_pk_exp",
    "9F2F": "icc_pin_pk_rem",
    "9F32": "ipke",
    "9F33": "terminal_capabilities",
    "9F34": "cvm_results",
    "9F35": "terminal_type",
    "9F36": "atc",
    "9F37": "unpredictable_number",
    "9F38": "pdol",
    "9F39": "pos_entry_mode",
    "9F3B": "icc_currency_code",
    "9F40": "additional_terminal_caps",
    "9F41": "trans_seq_counter",
    "9F42": "app_currency",
    "9F43": "icc_currency_exp",
    "9F44": "app_currency_exponent",
    "9F45": "data_auth_code",
    "9F46": "icc_pk_cert",
    "9F47": "icc_pk_exponent",
    "9F48": "icc_pk_remainder",
    "9F49": "ddol",
    "9F4A": "data_auth_tags",
    "9F4B": "sdad",
    "9F4C": "icc_dynamic_number",
    "9F4E": "merchant_name",
    "9F53": "trans_category_code",
    "9F5B": "dsdol",
    "9F5C": "mdol",
    "9F6A": "unpredictable_number_numeric",
    "A5": "fci_prop",
    "C5": "card_issuer_action",
    "DF0C": "kernal_id",
    "DF20": "ipb",
    "DF21": "iaf"
}

EMV_NAMES_TO_TAGS = {value: key for key, value in EMV_TAGS_TO_NAMES.items()}
