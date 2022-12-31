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
        super().__init__(
            "objstm.pdf",
            process_data=True,
            process_tags=False,
            filter_=True,
            strings=["/Pages"],
            hexa=["000102"],
            regexs=["[0-9a-f]{32}"],
            types=["xref"],
            ids=[2],
        )

    def handle(self, type_: str, data: bytes, typename: str = "") -> None:
        print(type_, data, typename)


parser = MyPDFparser()
parser.parse()
print(parser.report())
