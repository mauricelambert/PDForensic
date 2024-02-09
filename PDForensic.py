#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool analyses PDF files for Forensic Investigations
#    Copyright (C) 2022, 2023, 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

r"""
This tool analyses PDF files for Forensic Investigations

~# cat blank.pdf | python3.11 PDForensic.py - *.pdf ../*.pdf https://www.pdfscripting.com/public/FreeStuff/PDFSamples/TheFlyv3_EN4Rdr.pdf
...
~# python3.11 PDForensic.py blank.pdf
0         pdf_tag                   b'%PDF-1.6\r'
1         type                      ObjStm
2         type                      ObjStm
3         type                      XRef
4         type                      Outlines
5         subtype                   Type1
5         type                      Font
7         type                      Pages
9         subtype                   XML
9         type                      Metadata
10        date                      b"D:20060216150351-08'00'"
10        date                      b"D:20080816125100-07'00'"
15        date                      b"D:20080816125100-07'00'"
15        type                      TransformParams
15        type                      SigRef
15        type                      Sig
15        acroform                  b'/AcroForm 21 0 R/'
15        type                      Catalog
17        scripts                   b'/JavaScript'
19        scripts                   b'/JavaScript/JS'
21        type                      OCG
22        type                      Page
23        subtype                   Widget
23        type                      Annot
24        subtype                   Form
24        type                      XObject
25        subtype                   Form
25        type                      XObject
27        subtype                   Image
27        type                      XObject
28        subtype                   Image
28        type                      XObject
29        subtype                   Widget
29        type                      Annot
30        subtype                   Form
30        type                      XObject
31        subtype                   Form
31        type                      XObject
32        subtype                   Form
32        type                      XObject
33        subtype                   Form
33        type                      XObject
34        subtype                   Widget
34        type                      Annot
35        subtype                   Form
35        type                      XObject
36        subtype                   Form
36        type                      XObject
37        subtype                   Form
37        type                      XObject
38        subtype                   Form
38        type                      XObject
39        subtype                   Widget
39        type                      Annot
40        subtype                   Form
40        type                      XObject
41        subtype                   Form
41        type                      XObject
42        subtype                   Form
42        type                      XObject
43        subtype                   Form
43        type                      XObject
44        subtype                   Widget
44        type                      Annot
45        subtype                   Form
45        type                      XObject
46        subtype                   Type1
46        type                      Font
47        type                      Encoding
48        subtype                   Link
48        type                      Border
48        type                      Annot
49        subtype                   Widget
49        type                      Annot
50        subtype                   Form
50        type                      XObject
51        subtype                   Type1
51        type                      Font
52        subtype                   Widget
52        type                      Annot
53        subtype                   Form
53        type                      XObject
54        subtype                   Form
54        type                      XObject
55        subtype                   Widget
55        type                      Annot
56        subtype                   Form
56        type                      XObject
57        subtype                   Form
57        type                      XObject
58        subtype                   Widget
58        type                      Annot
59        subtype                   Form
59        type                      XObject
60        subtype                   Widget
60        type                      Annot
61        subtype                   Form
61        type                      XObject
62        subtype                   Form
62        type                      XObject
63        subtype                   Image
63        type                      XObject
64        subtype                   Widget
64        type                      Annot
65        subtype                   Form
65        type                      XObject
66        subtype                   Form
66        type                      XObject
67        subtype                   Form
67        type                      XObject
68        subtype                   Popup
68        type                      Annot
69        subtype                   Widget
69        type                      Annot
70        subtype                   Form
70        type                      XObject
71        subtype                   Type1
71        type                      Font
72        type                      Encoding
74        subtype                   TrueType
74        type                      Font
75        subtype                   TrueType
75        type                      Font
76        subtype                   TrueType
76        type                      Font
77        subtype                   TrueType
77        type                      Font
78        URI                       b'/URI(http://www.pdfscripting.com)/S/URI>>'
79        scripts                   b'/JavaScript/JS(\\nif\\(this.bouncing\\)\\r\\n{\\r\\n\tthis.bouncing = false;\\r\\n\tapp.clearInterval\\(this.bounceTime\\);\\r\\n\tthis.bounceTime = null;\\r\\n}\\r\\n\\r\\n//app.clearInterval\\(timer\\); // stop timer\\r\\n//app.clearTimeOut\\(timeout\\); // stop timer\\r\\n\\r\\n\\r\\n\\r)>>'
81        scripts                   b'/JavaScript/JS'
83        scripts                   b'/JavaScript/JS(\\nXinc = 5;\\r\\nYinc = 5;\\r\\n\\r\\n\\r)>>'
84        scripts                   b'/JavaScript/JS(\\nXinc = 3;\\r\\nYinc = 3;\\r\\n\\r\\n\\r)>>'
85        scripts                   b'/JavaScript/JS(\\nXinc = 1;\\r\\nYinc = 1;\\r\\n\\r)>>'
86        scripts                   b'/JavaScript/JS'
89        subtype                   Image
89        type                      XObject
91        type                      FontDescriptor
93        type                      FontDescriptor
94        type                      FontDescriptor
95        type                      ExtGState
96        type                      ExtGState
97        URI                       b'/URI(http://www.windjack.com)/S/URI>>'
98        xref                      
99        xref                      
100       startxref                 
101       eof_tag                   b'%%EOF\r'
{
    "tool": "PDForensic",
    "version": "0.0.1",
    "file": "<http.client.HTTPResponse object at 0x7f4cbbc6fd60>",
    "date": "2022-12-27T18:53:59.873367",
    "malicious": {
        "score": "26%",
        "types": [
            "acroform",
            "scripts",
            "URI"
        ]
    },
    "objects": {
        "found": 102,
        "processed": 146,
        "counter": {
            "type - XObject": 31,
            "subtype - Form": 27,
            "type - Annot": 14,
            "subtype - Widget": 12,
            "type - Font": 8,
            "subtype - Type1": 4,
            "subtype - Image": 4,
            "subtype - TrueType": 4,
            "type - FontDescriptor": 3,
            "type - ObjStm": 2,
            "type - Encoding": 2,
            "type - ExtGState": 2,
            "type - XRef": 1,
            "type - Outlines": 1,
            "type - Pages": 1,
            "subtype - XML": 1,
            "type - Metadata": 1,
            "type - TransformParams": 1,
            "type - SigRef": 1,
            "type - Sig": 1,
            "type - Catalog": 1,
            "type - OCG": 1,
            "type - Page": 1,
            "subtype - Link": 1,
            "type - Border": 1,
            "subtype - Popup": 1
        }
    },
    "filters": {
        "ids": [],
        "types": [],
        "regex": [],
        "strings": [],
        "raw data - hexadecimal": []
    }
}
~# python3.11 PDForensic.py objstm.pdf --data --types objstm --no-csv --no-json
0         pdf_tag                   b'%PDF-1.5\n'
1         object                    b'1 0 obj\n<< /Type /ObjStm /Length 236 /N 4 /First 20 >>\nstream\n2 0 3 34 4 78 5 143\n<< /Pages 3 0 R /Type /Catalog >>\n<< /Count 1 /Kids [ 4 0 R ] /Type /Pages >>\n<< /Contents 6 0 R /Parent 3 0 R /Resources 5 0 R /Type /Page >>\n<< /Font << /F1 << /BaseFont /Arial /Subtype /Type1 /Type /Font >> >> >>\nendstream\nendobj'
4         startxref                 
5         eof_tag                   b'%%EOF\n'
{
    "tool": "PDForensic",
    "version": "0.0.1",
    "file": "objstm.pdf",
    "date": "2022-12-27T19:42:13.226314",
    "malicious": {
        "score": "0%",
        "types": []
    },
    "objects": {
        "found": 6,
        "processed": 4,
        "counter": {
            "type - ObjStm ": 1,
            "type - XRef ": 1
        }
    },
    "filters": {
        "ids": [],
        "types": [
            "objstm"
        ],
        "regex": [],
        "strings": [],
        "raw data - hexadecimal": []
    }
}
~# python3.11 PDForensic.py https://www.pdfscripting.com/public/FreeStuff/PDFSamples/TheFlyv3_EN4Rdr.pdf --data --ids 79 83 --ids 84 --strings URI --no-csv --no-json
0         pdf_tag                   b'%PDF-1.6\r'
78        object                    b'87 0 obj\r<</URI(http://www.pdfscripting.com)/S/URI>>\rendobj'
79        object                    b'89 0 obj\r<</S/JavaScript/JS(\\nif\\(this.bouncing\\)\\r\\n{\\r\\n\tthis.bouncing = false;\\r\\n\tapp.clearInterval\\(this.bounceTime\\);\\r\\n\tthis.bounceTime = null;\\r\\n}\\r\\n\\r\\n//app.clearInterval\\(timer\\); // stop timer\\r\\n//app.clearTimeOut\\(timeout\\); // stop timer\\r\\n\\r\\n\\r\\n\\r)>>\rendobj'
83        object                    b'94 0 obj\r<</S/JavaScript/JS(\\nXinc = 5;\\r\\nYinc = 5;\\r\\n\\r\\n\\r)>>\rendobj'
84        object                    b'95 0 obj\r<</S/JavaScript/JS(\\nXinc = 3;\\r\\nYinc = 3;\\r\\n\\r\\n\\r)>>\rendobj'
97        object                    b'108 0 obj\r<</URI(http://www.windjack.com)/S/URI>>\rendobj'
98        xref                      
99        xref                      
100       startxref                 
101       eof_tag                   b'%%EOF\r'
{
    "tool": "PDForensic",
    "version": "0.0.1",
    "file": "<http.client.HTTPResponse object at 0x7fd5329a4760>",
    "date": "2022-12-27T19:44:38.964000",
    "malicious": {
        "score": "26%",
        "types": [
            "acroform",
            "scripts",
            "URI"
        ]
    },
    "objects": {
        "found": 102,
        "processed": 10,
        "counter": {
            "type - XObject": 31,
            "subtype - Form": 27,
            "type - Annot": 14,
            "subtype - Widget": 12,
            "type - Font": 8,
            "subtype - Type1": 4,
            "subtype - Image": 4,
            "subtype - TrueType": 4,
            "type - FontDescriptor": 3,
            "type - ObjStm": 2,
            "type - Encoding": 2,
            "type - ExtGState": 2,
            "type - XRef": 1,
            "type - Outlines": 1,
            "type - Pages": 1,
            "subtype - XML": 1,
            "type - Metadata": 1,
            "type - TransformParams": 1,
            "type - SigRef": 1,
            "type - Sig": 1,
            "type - Catalog": 1,
            "type - OCG": 1,
            "type - Page": 1,
            "subtype - Link": 1,
            "type - Border": 1,
            "subtype - Popup": 1
        }
    },
    "filters": {
        "ids": [
            83,
            84,
            79
        ],
        "types": [],
        "regex": [],
        "strings": [
            "URI"
        ],
        "raw data - hexadecimal": []
    }
}
~# python3.11 PDForensic.py objstm.pdf --data --logs 20 --regex '[0-9a-f]{32}' --no-csv --no-json
0         pdf_tag                   b'%PDF-1.5\n'
[2022-12-27 19:54:14] INFO     (20) {PDForensic - PDForensic.py:634} Object 3 match the 'regex' filter.
3         object                    b'7 0 obj\n<< /Type /XRef /Length 32 /W [ 1 2 1 ] /Root 2 0 R /Size 8 /ID [<98e68406a8333cc2a3429ac0e8aa1fed><05fa7af561f775eeb73f00cd09fe19e7>] >>\nstream\n\x00\x00\x00\x00\x01\x00\x0f\x00\x02\x00\x01\x00\x02\x00\x01\x01\x02\x00\x01\x02\x02\x00\x01\x03\x01\x01J\x00\x01\x01\xb4\x00\nendstream\nendobj'
4         startxref                 
5         eof_tag                   b'%%EOF\n'
{
    "tool": "PDForensic",
    "version": "0.0.1",
    "file": "objstm.pdf",
    "date": "2022-12-27T19:54:14.196113",
    "malicious": {
        "score": "0%",
        "types": []
    },
    "objects": {
        "found": 6,
        "processed": 4,
        "counter": {
            "type - ObjStm ": 1,
            "type - XRef ": 1
        }
    },
    "filters": {
        "ids": [],
        "types": [],
        "strings": [],
        "regex": [
            "[0-9a-f]{32}"
        ],
        "raw data - hexadecimal": []
    }
}
~# python3.11 PDForensic.py objstm.pdf --data --hexa 000102
0         pdf_tag                   b'%PDF-1.5\n'
3         object                    b'7 0 obj\n<< /Type /XRef /Length 32 /W [ 1 2 1 ] /Root 2 0 R /Size 8 /ID [<98e68406a8333cc2a3429ac0e8aa1fed><05fa7af561f775eeb73f00cd09fe19e7>] >>\nstream\n\x00\x00\x00\x00\x01\x00\x0f\x00\x02\x00\x01\x00\x02\x00\x01\x01\x02\x00\x01\x02\x02\x00\x01\x03\x01\x01J\x00\x01\x01\xb4\x00\nendstream\nendobj'
4         startxref                 
5         eof_tag                   b'%%EOF\n'
{
    "tool": "PDForensic",
    "version": "0.0.1",
    "file": "objstm.pdf",
    "date": "2022-12-27T20:05:19.538251",
    "malicious": {
        "score": "0%",
        "types": []
    },
    "objects": {
        "found": 6,
        "processed": 4,
        "counter": {
            "type - ObjStm ": 1,
            "type - XRef ": 1
        }
    },
    "filters": {
        "ids": [],
        "types": [],
        "strings": [],
        "regex": [],
        "raw data - hexadecimal": [
            "000102"
        ]
    }
}
~# 

>>> from PDForensic import PDForensic
>>> class MyPDFparser(PDForensic):
...     def __init__(self):
...         super().__init__("objstm.pdf")
...     def handle(self, type_: str, data: bytes, typename: str = "") -> None:
...         print(type_, data, typename)
>>> parser = MyPDFparser()
>>> parser.parse()
pdf_tag b'%PDF-1.5\n' 
stream_object b'< /Type /ObjStm /' 
type b'/Type /XRef ' XRef 
startxref b'startxref\n436\n' 
eof_tag b'%%EOF\n' 
>>> print(parser.report())
{'tool': 'PDForensic', 'version': '0.0.1', 'file': 'objstm.pdf', 'date': '2022-12-27T20:26:27.425086', 'malicious': {'score': '10%', 'types': ['stream_object']}, 'objects': {'found': 6, 'processed': 5, 'counter': {'type - XRef ': 1}}, 'filters': {'ids': [], 'types': [], 'strings': [], 'regex': [], 'raw data - hexadecimal': []}}
>>> class MyPDFparser(PDForensic):
...     def __init__(self):
...         super().__init__("objstm.pdf", process_data = True, process_tags = False, filter_ = True, strings = ["/Pages"], hexa = ["000102"], regexs = ['[0-9a-f]{32}'], types = ["xref"], ids = [2])
...     def handle(self, type_: str, data: bytes, typename: str = "") -> None:
...         print(type_, data, typename)
>>> parser = MyPDFparser()
>>> parser.parse()
pdf_tag b'%PDF-1.5\n' 
object b'1 0 obj\n<< /Type /ObjStm /Length 236 /N 4 /First 20 >>\nstream\n2 0 3 34 4 78 5 143\n<< /Pages 3 0 R /Type /Catalog >>\n<< /Count 1 /Kids [ 4 0 R ] /Type /Pages >>\n<< /Contents 6 0 R /Parent 3 0 R /Resources 5 0 R /Type /Page >>\n<< /Font << /F1 << /BaseFont /Arial /Subtype /Type1 /Type /Font >> >> >>\nendstream\nendobj' 
object b"6 0 obj\n<< /Length 57 >>\nstream\nq\nBT\n/F1 55 Tf\n10 400 Td\n(http://www.corkami.com) '\nET\nQ\nendstream\nendobj" 
object b'7 0 obj\n<< /Type /XRef /Length 32 /W [ 1 2 1 ] /Root 2 0 R /Size 8 /ID [<98e68406a8333cc2a3429ac0e8aa1fed><05fa7af561f775eeb73f00cd09fe19e7>] >>\nstream\n\x00\x00\x00\x00\x01\x00\x0f\x00\x02\x00\x01\x00\x02\x00\x01\x01\x02\x00\x01\x02\x02\x00\x01\x03\x01\x01J\x00\x01\x01\xb4\x00\nendstream\nendobj' 
startxref b'startxref\n436\n' 
eof_tag b'%%EOF\n' 
>>> print(parser.report())
{'tool': 'PDForensic', 'version': '0.0.1', 'file': 'objstm.pdf', 'date': '2022-12-27T20:38:38.078297', 'malicious': {'score': '10%', 'types': ['stream_object']}, 'objects': {'found': 6, 'processed': 6, 'counter': {'type - XRef ': 1}}, 'filters': {'ids': [2], 'types': ['xref'], 'strings': ['/Pages'], 'regex': ['[0-9a-f]{32}'], 'raw data - hexadecimal': ['000102']}}
>>> 
"""

__version__ = "0.2.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This tool analyses PDF files for Forensic Investigations"
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/PDForensic"

copyright = """
PDForensic  Copyright (C) 2022, 2023, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["PDForensic"]

print(copyright)

from zlib import (
    decompress as zlib,
    decompressobj as zlib_object,
    error as zliberror,
)
from logging import StreamHandler, Formatter, Logger, getLogger
from typing import Dict, Union, Tuple, Iterable, List
from sys import stdout, stderr, stdin, _getframe
from re import compile as regex, Pattern, Match
from argparse import ArgumentParser, Namespace
from base64 import b16decode, b16encode
from os.path import basename, splitext
from collections.abc import Callable
from abc import ABC, abstractmethod
from urllib.request import urlopen
from contextlib import suppress
from collections import Counter
from binascii import unhexlify
from datetime import datetime
from _io import TextIOWrapper
from io import BytesIO
from glob import iglob
from csv import writer
from json import dump
from math import ceil

pdf_parser: Pattern = regex(
    r"""(?xs)
(?P<null>
    \d+\s+\d+\s+obj\s+null\s+endobj
) |
(?P<boolean>
    \d+\s+\d+\s+obj\s+(true|false)\s+endobj
) |
(?P<integer>
    \d+\s+\d+\s+obj\s+-?\d+\s+endobj
) |
(?P<number>
    \d+\s+\d+\s+obj\s+-?\d+\.\d+\s+endobj
) |
(?P<ref>
    \d+\s+\d+\s+obj\s+\d+\s\d+\sR\s+endobj
) |
(?P<string>
    \d+\s+\d+\s+obj\s+\([\x00-\xff]+\)\s+endobj
) |
(?P<array>
    \d+\s+\d+\s+obj\s+\[\s*((-?\d+(\.\d+)?|R|\([\x00-\xff]+?\)|<+[\x00-\xff]+?>+|\[[\x00-\xff]*?\]|true|false|null|/\w+)\s+)*(-?\d+(\.\d+)?|R|\([\x00-\xff]+\)|<+[\x00-\xff]+?>+|\[[\x00-\xff]*?\]|true|false|null|/\w+)\s*\]\s+endobj
) |
(?P<object>
    (\d+\s+\d+\s+obj(\s+<+[\x00-\xff]+?>+))(\s*stream\s([\x00-\xff]*?)(\sendstream)\s+endobj\s|\s+endobj\s)
) |
(?P<root>
    <+((/ID\s*\[\s*(<[\da-fA-F]+>){1,2}\])|[^>])*?/Root((/ID\s*\[\s*(<[\da-fA-F]+>){1,2}\])|[^>])*?>+
) |
(?P<pdf_tag>
    %PDF(-\d+\.\d+)?\s
) |
(?P<eof_tag>
    %%EOF\s?
) |
(?P<binary_tag>
    %[\x00-\xff]{4}\s
) |
(?P<startxref>
    startxref\s+\d+\s+
) |
(?P<xref>
    xref[\n\r\w ]+?trailer\s+
) |
(?P<unknow_object>
    \d+\s+\d+\s+obj[\x00-\xff]+?endobj
) |
(?P<unknow_token>
    [^\x00\t\x0c\x20\r\n]+
)
""".encode()
)

tags_parser: Pattern = regex(
    r"""(?xi)
(?P<command>
    \s<+[\x00-\xff]+/Launch[\x00-\xff]+$                                             # Launch can launch a command
) |
(?P<AA_script_starter>
    \s<+[\x00-\xff]+/AA\s*<+[\x00-\xff]+$                                            # Start run automatically scripts
) |endstream\rendobj
(?P<OpenAction_script_starter>
    \s<+[\x00-\xff]+/OpenAction[\x00-\xff]+$                                         # Start run automatically scripts
) |
(?P<scripts>
    \s<+[\x00-\xff]+/JavaScript(\s*/JS(\([\x00-\xff]+\)[\x00-\xff]+)?)?[\x00-\xff]+$ # Javascript code
) |
(?P<stream_object>
    \s<+[\x00-\xff]+/ObjStm\s*(/|>)                                                  # Hide object in stream
) |
(?P<URI>
    \s<+[\x00-\xff]+/URI[\x00-\xff]+$                                                # Access resource by its URL
) |
(?P<form>
    \s<+[\x00-\xff]+/SubmitForm[\x00-\xff]+$                                         # Send data to server
) |
(?P<send>
    \s<+[\x00-\xff]+/GoTo(R|E)[\x00-\xff]+$                                          # Send data to server
) |
(?P<embedded>
    \s<+[\x00-\xff]+/EmbeddedFile[\x00-\xff]+$                                       # Access resource by its URL
) |
(?P<GoTo>
    \s<+[\x00-\xff]+/GoTo\s*/[\x00-\xff]+$                                           # Change the view to a specified destination
) |
(?P<acroform>
    \s<+[\x00-\xff]+/AcroForm[\w\s]*(/|>)
) |
(?P<malicious_image>
    \s<+[\x00-\xff]+/JBIG2Decode\s*(/|>)
) |
(?P<media>
    \s<+[\x00-\xff]+/RichMedia[\x00-\xff]+$                                          # RichMedia can be used to embed Flash in a PDF
) |
(?P<date>
    D:(\d{14})[-+Z]?(\d{2}'\d{2}')?
) |
(?P<type>
    /Type\s*/[\w\s]+
) |
(?P<subtype>
    /Subtype\s*/[\w\s]+
)
""".encode()
)

pdf_tags_char: Pattern = regex(r"#[0-9a-fA-F]{2}".encode())

pdf_string_char: Pattern = regex(r"\\[0-7]{1,3}".encode())

pdf_filters: Pattern = regex(r"/Filter\s*(/\w+|\[(/\w+\s*)+\])".encode())

pdf_streams: Pattern = regex(
    r"\s?stream\s[\x00-\xff]+\sendstream"
)


def hex_decode(data: bytes) -> bytes:
    r"""
    This function decodes hexadecimal encoding (ASCIIHexDecode filter).

    >>> hex_decode(b"05020a 0 a 02>")
    b'\x05\x02\n\n\x02'
    >>>
    """

    return unhexlify(b"".join(data.rstrip(b">").split()))


def deflate(data: bytes) -> bytes:
    r"""
    This function decodes zlib compressed streams (FlateDecode filter).

    >>> deflate(b'x\x9cK\xcb\xcf\x07\x00\x02\x82\x01E')
    b'foo'
    >>> deflate(b'x\x9cJ\xcb\xcf\x07\x00foo')
    b'foofoo'
    >>> deflate(b'foo')
    b'foo'
    >>>
    """

    with suppress(zliberror):
        return zlib(data)

    # data_length = len(data)
    zlib_instance = zlib_object()
    uncompressed = bytearray()
    for index, byte in enumerate(data):
        try:
            uncompressed.extend(
                zlib_instance.decompress(byte.to_bytes(1, "big"))
            )
        except:
            break

    if index < 3:
        return data

    return bytes(uncompressed) + data[index:]


# https://pdfbox.apache.org/docs/1.8.12/javadocs/org/apache/pdfbox/filter/RunLengthDecodeFilter.html
# https://gogit.univ-orleans.fr/lifo/no/openboard/blob/a53f41f71b8346e263e44e146d6e0853e20f4867/src/pdf-merger/RunLengthDecode.cpp


def runlength_decode(data: bytes) -> bytes:
    r"""
    This function decodes streams with filter RunLengthDecode.

    >>> runlength_decode(b'\x030123\xffa\x80')
    b'0123aa'
    >>> runlength_decode(b'\x000\xffa')
    b'0aa'
    >>>
    """

    uncompressed = bytearray()

    characters = BytesIO(data)
    character = characters.read(1)

    while character:
        character = int.from_bytes(characters, "big")
        if character < 128:
            uncompressed.extend(characters.read(character + 1))
        elif character > 128:
            uncompressed.extend(characters.read(1) * (257 - character))
        else:
            break
        character = characters.read(1)

    return bytes(uncompressed)


def a85decode(data: bytes) -> bytes:
    r"""
    This function decodes ascii 85.

    >>> a85decode(b'0AZauzaZbv~foobar')
    b'/\xde\x02D\x00\x00\x00\x00\xc9>'
    >>>
    """

    new_data = bytearray()
    position = block = 0
    for character in data:
        if 32 < character < 118:
            position += 1
            block = block * 85 + character - 33
            if position == 5:
                new_data.extend(block.to_bytes(4, "big"))
                position = block = 0
        elif character == 122:
            new_data.extend(b"\0" * 4)
        elif character == 126:
            if position:
                [block := block * 85 + 84 for _ in range(position, 5)]
                new_data.extend(block.to_bytes(4, "big")[: position - 1])
            break
    return bytes(new_data)


# https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf
# http://paulbourke.net/dataformats/postscript/psref.pdf
# https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Welch
# https://github.com/empira/PDFsharp/blob/master/src/PdfSharp/Pdf.Filters/LzwDecode.cs
# https://github.com/katjas/PDFrenderer/blob/master/src/com/sun/pdfview/decode/LZWDecode.java

# http://www-igm.univ-mlv.fr/~lecroq/cours/lzw.pdf
# https://www.normalesup.org/~simonet/teaching/caml-prepa/tp-caml-2001-07.pdf
# https://perso.limsi.fr/anne/coursAlgo/lzwAS.pdf

# https://github.com/hhrutter/lzw/blob/master/reader.go
# https://github.com/gettalong/hexapdf/blob/b9e194418b3b1bf89d6842e264dbff1c348c1332/lib/hexapdf/filter/lzw_decode.rb
# https://github.com/tecnickcom/tc-lib-pdf-filter/blob/c56027589f3e9456c469feaf3a7987cb796f9a44/src/Type/Lzw.php


class LzwDecode:
    r"""
    This class decodes LZW compressed data.

    >>> decoder = LzwDecode()
    >>> decoder.decode(b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    b'-----A---B'
    >>> decoder.decode(b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01')
    b'-----A---B'
    >>>
    """

    bits_number_table = {511: 10, 1023: 11, 2047: 12}

    def __init__(self):
        self.character = 0
        self.bits_number = 9
        self.byte = b"\0"
        self.bits_index = 8
        self.precedent_bytes: bytes = None
        self.file = BytesIO()
        self.uncompressed = bytearray()
        self.code = 0

    def decode(self, data: bytes) -> bytes:
        """
        This function decodes compressed data.
        """

        self.code = 0
        self.byte = b"\0"
        self.uncompressed.clear()
        position = self.file.tell()
        self.file.write(data)
        self.file.seek(position)

        while self.byte and self.code != 257:
            self.shift = 8 - self.bits_index
            self.code = 0
            bits = self.bits_number
            while self.byte and self.bits_number > self.shift:
                self.read_block()
            self.code = (self.code << self.bits_number) | (
                (self.character >> (self.shift - self.bits_number))
                & ((1 << self.bits_number) - 1)
            )
            self.bits_index += self.bits_number
            self.bits_number = bits
            self.do_code()

        return bytes(self.uncompressed)

    def read_block(self) -> None:
        """
        This function reads a LZW block.
        """

        self.code = (self.code << self.shift) | (
            self.character & ((1 << self.shift) - 1)
        )
        self.bits_number -= self.shift
        self.byte = self.file.read(1)
        self.character = int.from_bytes(self.byte, "big")
        self.bits_index = 0
        self.shift = 8 - self.bits_index

    def do_code(self) -> None:
        """
        This function makes actions for the specific code.
        """

        if self.code == 256:
            self.table = [x.to_bytes(1, "big") for x in range(256)]
            self.table.extend((None, None))
            self.precedent_bytes = b""
            self.bits_number = 9
        elif not self.precedent_bytes:
            self.precedent_bytes = self.table[self.code]
            self.uncompressed.extend(self.precedent_bytes)
        elif self.code != 257:
            if self.code < len(self.table):
                x = self.table[self.code]
                self.uncompressed.extend(x)
                self.table.append(
                    self.precedent_bytes + x[0].to_bytes(1, "big")
                )
            else:
                self.table.append(
                    self.precedent_bytes
                    + self.precedent_bytes[0].to_bytes(1, "big")
                )
                x = self.table[self.code]
                self.uncompressed.extend(x)
            self.bits_number = LzwDecode.bits_number_table.get(
                len(self.table), self.bits_number
            )
            self.precedent_bytes = x


lzwdecode = LzwDecode().decode


class PDForensic(ABC):

    """
    This class parses and analyses PDF files for Forensic Investigations.
    """

    malicious_scoring: Dict[str, int] = {
        "command": 100,
        "scripts": 100,
        "AA_script_starter": 75,
        "OpenAction_script_starter": 75,
        "stream_object": 50,
        "URI": 25,
        "form": 25,
        "send": 25,
        "embedded": 25,
        "GoTo": 15,
        "acroform": 15,
        "malicious_image": 10,
        "media": 10,
    }

    filters = {
        "LZWDecode": lzwdecode,
        "LZW": lzwdecode,
        "ASCII85Decode": a85decode,
        "A85": a85decode,
        "ASCIIHexDecode": hex_decode,
        "AHx": hex_decode,
        "FlateDecode": deflate,
        "Fl": deflate,
        "RunLengthDecode": runlength_decode,
        "R": runlength_decode,
    }

    def __init__(
        self,
        file: str,
        process_data: bool = False,
        process_tags: bool = True,
        filter_: bool = True,
        strings: Iterable[str] = [],
        hexa: Iterable[str] = [],
        regexs: Iterable[str] = [],
        types: Iterable[str] = [],
        ids: Iterable[int] = [],
    ):
        self.hexa = {b16decode(string.encode().upper()) for string in hexa}
        self.types = {string.strip().casefold() for string in types}
        self.regex = {regex(string.encode()) for string in regexs}
        self.strings = {string.encode() for string in strings}
        self.ids = {integer for integer in ids}

        self.custom_filter = (
            len(self.hexa)
            + len(self.regex)
            + len(self.strings)
            + len(self.types)
            + len(self.ids)
        )

        self.process_data = process_data
        self.process_tags = process_tags
        self.type_counter = Counter()
        self.use_filter = filter_
        self.current_id = 0
        self.exit_code = 0
        self.processed = 0
        self.file = file
        self.score = {}
        self._start = 0
        self.count = 0
        self._end = 0

        if not filter_ and (
            self.hexa or self.regex or self.strings or self.types
        ):
            logger_warning("Filters are not used but you add filter values.")

    def get_malicious_score(self) -> float:
        """
        This function calculates malicious score.
        """

        logger_debug("Getting malicious score for " + str(self.file))
        return (
            sum(self.score.values())
            * 100
            / sum(self.malicious_scoring.values())
        )

    def report(self) -> Dict[str, Union[str, int]]:
        """
        This function reports PDF analysis.
        """

        return {
            "tool": "PDForensic",
            "version": __version__,
            "file": str(self.file),
            "date": datetime.now().isoformat(),
            "malicious": {
                "score": str(ceil(self.get_malicious_score())) + "%",
                "types": list(self.score.keys()),
            },
            "objects": {
                "found": self.count,
                "processed": self.processed,
                "counter": {k: v for k, v in self.type_counter.most_common()},
            },
            "filters": {
                "ids": list(self.ids),
                "types": list(self.types),
                "strings": [x.decode() for x in self.strings],
                "regex": [x.pattern.decode() for x in self.regex],
                "raw data - hexadecimal": [
                    b16encode(x).decode() for x in self.hexa
                ],
            },
        }

    def read_file(self) -> bytes:
        """
        This function returns data readed from PDF file.
        """

        logger_debug("Getting data for " + str(self.file))

        if isinstance(self.file, str):
            try:
                with open(self.file, "rb") as file:
                    return file.read()
            except Exception as e:
                logger_error("Can't open " + self.file + " error: " + str(e))
                self.exit_code += 5
                return None
        else:
            return self.file.read()

    def parse(self) -> None:
        """
        This function parses PDF data.
        """

        data = self.read_file()

        logger_debug("Start data parsing for " + str(self.file))
        for match in pdf_parser.finditer(data):
            self._start = match.start()
            self._end = match.end()
            data = match.group()
            id_ = data.split(maxsplit=1)[0]
            self.current_id = int(id_) if id_.isdigit() else -1

            if match.lastgroup == "object":
                processed = self.get_data_process(match)
            else:
                processed = self.to_handle(match.lastgroup, match.group())

            if self.current_id in self.ids:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'id' filter."
                )
                if not processed:
                    self.to_handle("object", data)
                    self.to_handle(
                        "decoded_data",
                        self.pdf_unfilter(match.group(16), data),
                    )

            self.count += 1

    @staticmethod
    def deobfuscation(tags: bytes) -> bytes:
        r"""
        This function deobfuscates tags.

        >>> PDForensic.deobfuscation(r'#61(\142)#63'.encode())
        b'a(b)c'
        >>> PDForensic.deobfuscation(r')'.encode())
        [2016-06-22 17:58:15] ERROR    (40) {PDForensic - PDForensic.py:722} PDF syntax error
        >>>
        """

        for char in pdf_tags_char.finditer(tags):
            char = char.group()
            tags = tags.replace(char, chr(int(char[1:], 16)).encode())

        start_index: int = None
        precedent: int = None

        for i, char in enumerate(tags):
            if precedent:
                continue

            if char == 40:
                start_index = i
            elif char == 41:
                end_index = i
                if start_index is None:
                    logger_error("PDF syntax error")
                    continue
                pdf_string = tags[start_index:end_index]
                for char in pdf_string_char.finditer(pdf_string):
                    char = char.group()
                    pdf_string = pdf_string.replace(
                        char, chr(int(char[1:], 8)).encode()
                    )
                tags = tags[:start_index] + pdf_string + tags[end_index:]

            precedent = char

        return tags

    def pdf_unfilter(self, tags: bytes, full_data: bytes) -> bytes:
        """
        This function decodes and decompress PDF streams.
        """

        filters = pdf_filters.search(tags)

        if filters is None:
            return full_data

        data = full_data[full_data.index(tags) + len(tags) :]
        data = data.split(b"endstream")[0].split(b"stream")[1].strip()

        for filter_ in filters.group(1).decode().strip("[]").split("/"):
            callback = PDForensic.filters.get(filter_)
            if filter_:
                if callback:
                    data = callback(data)
                else:
                    break
        else:
            return data

        return full_data

    def get_data_process(self, match: Match) -> bool:
        """
        This function sends only data to process to filters.
        """

        full_data = match.group()
        logger_debug("Getting tags for object " + str(self.current_id))
        tags = match.group(16)

        tags = self.deobfuscation(tags)

        if self.process_data:
            processed = self.filter(full_data)
        else:
            processed = self.filter(tags)

        logger_debug("Start tags analysis for object " + str(self.current_id))
        for tag in tags_parser.finditer(tags):
            group = tag.lastgroup
            data = tag.group()
            type_ = ""
            suspicious = False

            if group == "type":
                type_ = data.split(b"/")[2].strip().decode()
                processed = self.type_filter(type_, full_data, processed)
                self.type_counter["type - " + type_] += 1
            elif group == "subtype":
                type_ = data.split(b"/")[2].strip().decode()
                processed = self.type_filter(type_, full_data, processed)
                self.type_counter["subtype - " + type_] += 1
            elif group == "stream_object":
                StreamObjectParser(
                    self, self.pdf_unfilter(tags, full_data)
                ).parse()
                suspicious = True
            elif group != "date":
                suspicious = True

            if suspicious:
                logger_info(
                    "Getting suspicious tag: '"
                    + group
                    + "' for object "
                    + str(self.current_id)
                )
                self.score[group] = self.malicious_scoring[group]

            if not self.custom_filter:
                self.to_handle(group, data, type_)

        return processed

    def type_filter(
        self, type_: str, data: bytes, processed: bool = None
    ) -> bool:
        """
        This function filters objects by type.
        """

        if type_.strip().casefold() in self.types:
            logger_info(
                "Object " + str(self.current_id) + " match the 'type' filter."
            )
            if not processed:
                self.to_handle("object", data, type_)
            return True

    def filter(self, data: bytes, decoded_data: bytes = None) -> bool:
        """
        This function filters objects.
        """

        if not self.use_filter:
            self.to_handle("object", data)
            return True

        for string in self.strings:
            if string in data:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'string' filter."
                )
                self.to_handle("object", data)
                return True

        for raw in self.hexa:
            if raw in data:
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'hexadecimal' filter."
                )
                self.to_handle("object", data)
                return True

        for regex in self.regex:
            if regex.search(data):
                logger_info(
                    "Object "
                    + str(self.current_id)
                    + " match the 'regex' filter."
                )
                self.to_handle("object", data)
                return True

    def to_handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function calls inherited 'handle_object' methods.
        """

        self.processed += 1
        for class_ in self.__class__.__mro__:
            method = class_.__dict__.get("handle", lambda *x: None)
            if not getattr(method, "__isabstractmethod__", None):
                logger_debug(
                    "Object "
                    + str(self.current_id)
                    + " is processed by '"
                    + class_.__name__
                    + "'."
                )
                method(self, type_, data, typename)

    @abstractmethod
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        pass


class StreamObjectParser:

    """
    This class implements a stream object parser.
    """

    def __init__(self, forensic: PDForensic, data: bytes):
        self.forensic = forensic
        self.data = data

    def get_id_positions(self) -> List[Tuple[int, int]]:
        """
        This function returns IDs and position for each object in the stream.
        """

        data = self.data
        id_position = data.split(b" ", maxsplit=2)

        if len(id_position) == 3:
            id_, position, data = id_position
        else:
            return [], self.data

        id_positions = []
        add = id_positions.append
        while id_.isdigit() and position.isdigit():
            add((int(id_), int(position)))

            id_position = data.split(b" ", maxsplit=2)

            if len(id_position) == 3:
                id_, position, data = id_position
            else:
                break

        data = b" ".join((id_, position, data))
        return id_positions, data

    def parse(self) -> None:
        """
        This function processes tags in stream object.
        """

        id_positions, data = self.get_id_positions()
        forensic = self.forensic
        process_data = forensic.get_data_process

        for id_, position in id_positions[::-1]:
            forensic.current_id = id_
            process_data(
                type("Match", (), {"group": lambda *x: data[position:]})
            )
            data = data[:position]


class ToCSV(PDForensic):

    """
    This class saves filtered objects into a CSV report.
    """

    def __init__(self):
        filename = self.csv_filename = (
            splitext(basename(self.file))[0] + ".csv"
            if isinstance(self.file, str)
            else "not_named.csv"
        )
        file = self.csv_file = open(filename, "a")
        self.csv_writer = writer(file)

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function saves filtered objects into a CSV report.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "object"
            or type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            self.csv_writer.writerow(
                [
                    str(self.current_id),
                    type_,
                    typename,
                    str(self._start),
                    str(self._end),
                ]
            )
        else:
            self.csv_writer.writerow(
                [
                    str(self.current_id),
                    type_,
                    str(data),
                    str(self._start),
                    str(self._end),
                ]
            )


class Printer(PDForensic):

    """
    This class prints filtered objects.
    """

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function prints filtered objects.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            print(str(self.current_id).ljust(9), type_.ljust(25), typename)
        elif (
            type_ == "null"
            or type_ == "boolean"
            or type_ == "integer"
            or type_ == "number"
            or type_ == "ref"
            or type_ == "string"
            or type_ == "array"
        ):
            print(
                str(self.current_id).ljust(9),
                type_.ljust(25),
                repr(
                    data.split(b"endobj")[0]
                    .split(b"obj")[1]
                    .strip()
                    .decode("latin1")
                ),
            )
        else:
            print(
                str(self.current_id).ljust(9),
                type_.ljust(25),
                repr(data.decode("latin1")),
            )


class ToJSON(PDForensic):

    """
    This class saves filtered objects into a JSON report.
    """

    def __init__(self):
        filename = self.json_filename = (
            splitext(basename(self.file))[0] + ".json"
            if isinstance(self.file, str)
            else "not_named.json"
        )
        self.json_file = open(filename, "a")

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        """
        This function saves filtered objects into a JSON report.
        """

        if (not self.custom_filter and type_ == "object") or (
            type_ == "object"
            or type_ == "subtype"
            or type_ == "type"
            or type_ == "xref"
            or type_ == "startxref"
        ):
            dump(
                {
                    "id": str(self.current_id),
                    "type": type_,
                    "data": typename,
                    "start": self._start,
                    "end": self._end,
                },
                self.json_file,
            )
        else:
            dump(
                {
                    "id": str(self.current_id),
                    "type": type_,
                    "data": data.decode("latin-1"),
                    "start": self._start,
                    "end": self._end,
                },
                self.json_file,
            )
            self.json_file.write("\n")


def get_custom_logger(name: str = None) -> Logger:
    """
    This function create a custom logger.
    """

    logger = getLogger(name or _getframe().f_code.co_filename)
    logger.propagate = False

    if not logger.handlers:
        formatter = Formatter(
            fmt=(
                "%(asctime)s%(levelname)-9s(%(levelno)s) "
                "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
            ),
            datefmt="[%Y-%m-%d %H:%M:%S] ",
        )
        stream = StreamHandler(stream=stderr)
        stream.setFormatter(formatter)

        logger.addHandler(stream)

    return logger


def parse_args() -> Namespace:
    """
    This function parses command line arguments.
    """

    parser = ArgumentParser(
        description="This script parses and analyses PDF files for Forensic Investigations"
    )
    add_argument = parser.add_argument

    add_argument(
        "files",
        nargs="+",
        action="extend",
        help="Glob syntax, URL, '-' (stdin) to get PDF files data.",
    )
    add_argument(
        "-l",
        "--logs",
        type=int,
        default=51,
        help="Logs level (1 print all logs; 30 print warnings, error and critical)",
    )

    add_argument(
        "-c",
        "--no-csv",
        default=False,
        action="store_true",
        help="Deactivate CSV report",
    )
    add_argument(
        "-j",
        "--no-json",
        default=False,
        action="store_true",
        help="Deactivate JSON report",
    )
    add_argument(
        "-p",
        "--no-print",
        default=False,
        action="store_true",
        help="Deactivate printer",
    )

    group_data = parser.add_mutually_exclusive_group()
    group_data.add_argument(
        "-d",
        "--data",
        default=False,
        action="store_true",
        help="Process all data (tags, stream ect...)",
    )
    group_data.add_argument(
        "-t",
        "--tags",
        default=True,
        action="store_true",
        help="Process only tags.",
    )

    group_exclusive_filter = parser.add_mutually_exclusive_group()
    group_exclusive_filter.add_argument(
        "-f",
        "--no-filter",
        default=False,
        action="store_true",
        help="No filter, each object are processed",
    )

    group_filter = parser.add_argument_group(
        "Filter", description="Add custom elements to filter"
    )
    group_filter_add_argument = group_filter.add_argument
    group_filter_add_argument(
        "-s",
        "--strings",
        default=[],
        nargs="+",
        action="extend",
        help="Add string element to filter.",
    )
    group_filter_add_argument(
        "-r",
        "--regex",
        default=[],
        nargs="+",
        action="extend",
        help="Add regex element to filter.",
    )
    group_filter_add_argument(
        "-x",
        "--hexadecimal-data",
        "--hexa",
        default=[],
        nargs="+",
        action="extend",
        help="Add hexadecimal binary data element to filter.",
    )
    group_filter_add_argument(
        "-y",
        "--types",
        default=[],
        nargs="+",
        action="extend",
        help="Add a filter for PDF objects based on type name.",
    )
    group_filter_add_argument(
        "-i",
        "--ids",
        default=[],
        type=int,
        nargs="+",
        action="extend",
        help="Add a filter for PDF objects based on ID.",
    )

    return parser.parse_args()


def launch(
    code: int,
    file: str,
    arguments: Namespace,
    types: Iterable[type],
    report_file: TextIOWrapper,
) -> Tuple[int, bool]:
    """
    This function starts PDF file analysis.
    """

    logger_debug("Processing file '" + str(file) + "'")
    forensic = type("PdfAnalysis", types, {"__init__": PDForensic.__init__})(
        file,
        arguments.data,
        arguments.tags,
        not arguments.no_filter,
        arguments.strings,
        arguments.hexadecimal_data,
        arguments.regex,
        arguments.types,
        arguments.ids,
    )
    for type_ in types:
        init = type_.__dict__.get("__init__")
        if init:
            init(forensic)

    forensic.parse()
    report = forensic.report()
    dump(report, stdout, indent=4)
    dump(report, report_file)
    report_file.write("\n")
    print()

    return forensic.exit_code + code, True


def main() -> int:
    """
    This function starts this script from command line.
    """

    arguments = parse_args()

    logger.setLevel(arguments.logs)
    report = open(
        "PDForensic" + datetime.now().strftime("_%Y_%m_%d_%H_%M_%S") + ".json",
        "a",
    )

    types = []
    if not arguments.no_csv:
        types.append(ToCSV)
    if not arguments.no_json:
        types.append(ToJSON)
    if not arguments.no_print:
        types.append(Printer)
    if not types:
        logger_warning("Nothing to do without print, CSV or JSON. Add print.")
        types.append(Printer)
    types = tuple(types)

    exit_code = 0
    first_all = False

    for globsyntax in arguments.files:
        first = False
        logger_debug("Processing glob syntax '" + globsyntax + "'")

        if globsyntax == "-":
            exit_code, first = launch(
                exit_code, stdin.buffer, arguments, types, report
            )
            first_all = first
            continue
        elif ":" in globsyntax:
            exit_code, first = launch(
                exit_code, urlopen(globsyntax), arguments, types, report
            )
            first_all = first
            continue

        for file in iglob(globsyntax):
            exit_code, first = launch(
                exit_code, file, arguments, types, report
            )
            first_all = first

        if not first:
            logger_warning("There is no file matching: " + globsyntax)
            exit_code += 1

    report.close()
    if not first_all:
        logger_critical("There is no file found.")
        exit_code += 2

    return exit_code % 127


logger: Logger = get_custom_logger("PDForensic")
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical
logger_log: Callable = logger.log

if __name__ == "__main__":
    exit(main())
