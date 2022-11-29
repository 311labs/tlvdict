![](https://github.com/311labs/objict/workflows/tests/badge.svg)

## TLV - Type/Tag Length Format

Simple class that supports TLV encoding/decoding.

## Installation

```
pip install tlvdict
```


## Simple to use!

```python
>>> from tlvdict import TLVDict
>>> tlv = TLVDict.FromDict({"5F25": "200531", "9F06": "A0000000041010"})
>>> tlv
TLVDict([('5F25', '200531'), ('9F06', 'A0000000041010')])
>>> tlv.build()
'5F25032005319F0607A0000000041010'

>>> tlv2 = TLVDict.FromHex("5F25032005319F0607A0000000041010")
>>> tlv2
TLVDict([('5f25', '200531'), ('9f06', 'A0000000041010')])

```


