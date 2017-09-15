import struct

def toBYTE(x): return struct.unpack('<B',x)[0]
def toWORD(x): return struct.unpack('<H',x)[0]
def toDWORD(x): return struct.unpack('<I',x)[0]
def p16(x): return struct.pack('<H',x)