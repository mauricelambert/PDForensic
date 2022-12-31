![PDForensic logo](https://mauricelambert.github.io/info/python/security/PDForensic_small.png "PDForensic logo")

# PDForensic

## Description

This package analyses PDF files for Forensic Investigations.

## Requirements

This package require :
 - python3
 - python3 Standard Library

## Installation
```bash
pip install PDForensic
```

## Usages

### Command line

```bash
python3 -m PDForensic sample.pdf
python3 PDForensic.pyz sample.pdf
PDForensic sample.pdf

PDForensic objstm.pdf --data --hexa 000102
PDForensic objstm.pdf --data --types objstm --no-csv --no-json
PDForensic objstm.pdf --data --logs 20 --regex '[0-9a-f]{32}' --no-csv --no-json
cat blank.pdf | PDForensic - *.pdf ../*.pdf https://www.pdfscripting.com/public/FreeStuff/PDFSamples/TheFlyv3_EN4Rdr.pdf
PDForensic https://www.pdfscripting.com/public/FreeStuff/PDFSamples/TheFlyv3_EN4Rdr.pdf --data --ids 79 83 --ids 84 --strings URI --no-csv --no-json
```

### Python script

```python
from PDForensic import PDForensic

class MyPDFparser(PDForensic):
    def __init__(self):
        super().__init__("objstm.pdf")
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        print(type_, data, typename)
parser = MyPDFparser()
parser.parse()
print(parser.report())


class MyPDFparser(PDForensic):
    def __init__(self):
        super().__init__("objstm.pdf", process_data = True, process_tags = False, filter_ = True, strings = ["/Pages"], hexa = ["000102"], regexs = ['[0-9a-f]{32}'], types = ["xref"], ids = [2])
    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        print(type_, data, typename)
parser = MyPDFparser()
parser.parse()
print(parser.report())
```

## Links

 - [Github Page](https://github.com/mauricelambert/PDForensic/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/PDForensic.html)
 - [Pypi package](https://pypi.org/project/PDForensic/)
 - [Executable](https://mauricelambert.github.io/info/python/security/PDForensic.pyz)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
