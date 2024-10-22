import zlib
from zlib import crc32


class NotValidPngError(Exception):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)

    def __str__(self) -> str:
        strrc = "Input file is not a valid PNG File, "
        strrc += super().__str__()
        return strrc


class InvalidFileName(Exception):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)

    def __str__(self) -> str:
        strrc = "Input filename is not valid, "
        strrc += super().__str__()
        return strrc


class CrcChecksumError(Exception):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)

    def __str__(self) -> str:
        strrc = "CRC checksum failed, "
        strrc += super().__str__()
        return strrc


##
#   png.py is a png image file decomposer and reverse engineering tool, written solely as a side project by Roxon3000.  Script is also
#       capable of inserting text chunks into PNG files for educational/testing purposes.
##
#input args defaulted for convenience
message = "insert message here"
write_flag = False
fail_on_crc = True

idat_flag = False


def validateFileName(fn):
    #check for string type, even tho user input is string by default
    if not isinstance(fn, str):
        raise InvalidFileName("File name must be a string")
    #check to make sure filename is not empty even tho it will default to input.png
    if not fn or len(fn) < 1:
        raise InvalidFileName("File name must not be empty")


def validatePng(headerBytes_in):
    #137 80 78 71 13 10 26 10
    try:
        assert headerBytes_in[0] == 137
        assert headerBytes_in[1] == 80
        assert headerBytes_in[2] == 78
        assert headerBytes_in[3] == 71
        assert headerBytes_in[4] == 13
        assert headerBytes_in[5] == 10
        assert headerBytes_in[6] == 26
        assert headerBytes_in[7] == 10
    except AssertionError as exc:
        raise NotValidPngError(
            "Invalid PNG Header: must be 137 80 78 71 13 10 26 10") from exc


def getUnsignedBigInt(bytes_in):
    return int.from_bytes(bytes_in, byteorder="big", signed=False)


def parseIHDRChunk(ihdr_bytes):
    width = getUnsignedBigInt(ihdr_bytes[:4])
    height = getUnsignedBigInt(ihdr_bytes[4:8])
    bit_depth = getUnsignedBigInt(ihdr_bytes[8:9])
    colour_type = getUnsignedBigInt(ihdr_bytes[9:10])
    comp_method = getUnsignedBigInt(ihdr_bytes[10:11])
    filter_method = getUnsignedBigInt(ihdr_bytes[11:12])
    interlace_method = getUnsignedBigInt(ihdr_bytes[12:13])

    #validate IHDR vavlues are integer
    try:
        assert isinstance(width, int)
        assert isinstance(height, int)
        assert isinstance(bit_depth, int)
        assert isinstance(colour_type, int)
        assert isinstance(comp_method, int)
        assert isinstance(filter_method, int)
        assert isinstance(interlace_method, int)
    except AssertionError as exc:
        raise NotValidPngError("Invalid IHDR value") from exc

    return {
        'width': width,
        'height': height,
        'bit_depth': bit_depth,
        'colour_type': colour_type,
        'comp_method': comp_method,
        'filter_method': filter_method,
        'interlace_method': interlace_method
    }


def parseChunkType(chunk_header):
    chunklen_f = getUnsignedBigInt(chunk_header[:4])
    chunktype_f = chunk_header[4:].decode('ascii')

    return chunklen_f, chunktype_f


#start program

#user input
fileName = input("Enter File Name:")
fs = None

validateFileName(fileName)

with open(fileName, mode='rb+') as fs:

    try:
        headerBytes = fs.read(8)
        validatePng(headerBytes)

        #IHDR CHUNK (image header)
        chunklen, chunktype = parseChunkType(fs.read(8))
        chk = fs.tell()
        fs.seek(chk - 4)
        chunk_bytes = fs.read(chunklen + 4)
        ihdr = parseIHDRChunk(chunk_bytes[4:])
        print('ihdr', ihdr)
        ihdr_crc_bytes = fs.read(4)
        ihdr_crc = hex(getUnsignedBigInt(ihdr_crc_bytes))
        calc_crc = hex(crc32(chunk_bytes))
        assert ihdr_crc == calc_crc

        idat_compression_chunk = bytearray()

        xb = fs.read(8)
        while len(xb) > 0:
            xb_len, xb_type = parseChunkType(xb)
            print('chunk_type=', xb_type, 'chunk_length=', xb_len)
            ctell = fs.tell()
            fs.seek(ctell - 4)
            crc_chunk = fs.read(xb_len + 4)
            fs.seek(ctell)
            if xb_type == 'IEND' and write_flag:
                iend = bytearray(xb)
                iend_crc = bytearray(fs.read(4))
                ob_type = bytearray(b'tEXT')
                ob_null = b'\0'
                ob_keyword = b'mykey'
                ob = ob_keyword + ob_null + bytearray(str.encode(message))
                ob_length = bytearray(len(ob).to_bytes(4, byteorder='big'))
                ob_crc = int.to_bytes(crc32(ob_type + ob),
                                      length=4,
                                      byteorder='big',
                                      signed=False)
                sob = ob_length + ob_type + ob + ob_crc
                outchunk = sob + iend + iend_crc

                tell = fs.tell() - 12
                fs.seek(tell)
                fs.write(outchunk)
                fs.seek(tell)
                write_flag = False
                xb = fs.read(8)
                continue

            xb_chunk = fs.read(xb_len)

            if xb_type == 'IDAT':
                if idat_flag is False:
                    original_idat_tell = ctell
                idat_flag = True
                idat_compression_chunk = idat_compression_chunk + xb_chunk
            else:
                if idat_flag:
                    idat_flag = False
                    idat_raw = zlib.decompress(idat_compression_chunk)
                    print("Print decompressed image data")
                    for b in idat_raw[::ihdr["width"]]:
                        print(hex(int(b)), " ", end=" ")
                    print("")

            xb_crc_bytes = fs.read(4)
            xb_crc = hex(getUnsignedBigInt(xb_crc_bytes))
            calc_crc = hex(crc32(crc_chunk))
            # crc validation
            if xb_crc != calc_crc:
                if fail_on_crc:
                    raise CrcChecksumError(chunktype)
                print('xb_crc', xb_crc, 'does not equal calc_crc', calc_crc)

            xb = fs.read(8)
    except NotValidPngError as ex:
        print(ex)
    else:
        print("Successfully parsed png file")
    finally:
        #always close the file
        fs.close()
