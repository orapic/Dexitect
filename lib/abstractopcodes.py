# -*- coding: utf-8 -*-


# nop, monitor-enter, monitor-exit
NONE = ["NONE",0x0, [
    0x0,
    0x1d,0x1e
    ]]

# if-eq, if-ne
TEST = ["TEST", 0x1, [
    0x1f,
    0x2b,0x2c,
    0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,
    0x0100,0x0200
    ]]

# return-object, throw
END_OF_BASIC_BLOCK = ["ENDOFBASICBLOCK", 0x2, [
    0x0e,0x0f,0x10,0x11,
    0x27,0x28,0x29,0x2a
    ]]
 
# cmp-long, cmpl-float
COMPARISON = ["COMPARISON", 0x3, [
    0x20,
    0x2d,0x2e,0x2f,0x30,0x31
    ]]
 
# invoke-virtual, invoke-static
CALL = ["CALL", 0x4, [
    0x6e,0x6f,0x70,0x71,0x72,0x74,0x75,0x76,0x77,0x78,
    0xfa,0xfb,0xfc,0xfd
    ]]

# neg-int, not-int 
ARITHMETIC = ["ARITHMETIC", 0x5, [
    0x7b,0x7c,0x7d,0x7e,0x7f,0x80,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
    0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,
    0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0xe0,0xe1,0xe2
    ]]
 
# int-to-float, int-to-double
CAST = ["CAST", 0x6, [
    0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f
    ]]

# sget-object, sget-boolean
STATIC_FIELD_ACCESS = ["STATICFIELDACCESS", 0x7, [
    0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d
    ]]

# iput-wide, iput-byte
INSTANCE_FIELD_ACCESS = ["INSTANCEFIELDACCESS", 0x8, [
    0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
    ]]

# new-array, filled-new-array
ARRAY_ACCESS = ["ARRAYACCESS", 0x9, [
    0x21,0x23,0x24,0x25,0x26,
    0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,
    0x0300
    ]]
 
# const-string, const-string/jumbo
STRING = ["STRING", 0xa, [
    0x1a,0x1b
    ]]
 
# move-wide/16, move-wide/from16 const-class
MOVE = ["MOVE", 0xb, [
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,
    0x1c,
    0x22,
    0xfe,0xff
    ]]

# const/4, const/16
INTEGER = ["INTEGER", 0xc, [
    0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19
    ]]

ABSTRACT_FAMALIES = [NONE, TEST, END_OF_BASIC_BLOCK, COMPARISON, CALL, ARITHMETIC, CAST, STATIC_FIELD_ACCESS, INSTANCE_FIELD_ACCESS, ARRAY_ACCESS, STRING, MOVE, INTEGER]

def get_abstract_family_string(opcode):
    for family in ABSTRACT_FAMALIES:
        if opcode in family[-1]:
            return family[0]
    print("DEBUG: opcode family not found for opcode " + str(hex(opcode)) + " - ANTI ANALYSIS")
    return None
def get_abstract_family_value(opcode):
    for family in ABSTRACT_FAMALIES:
        if opcode in family[-1]:
            return family[1]
    print("DEBUG: opcode family not found for opcode " + str(hex(opcode)) + " - ANTI ANALYSIS")
    return None