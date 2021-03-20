#!/usr/bin/python3

import pefile

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100

pe = pefile.PE('test.exe')

def get_characteristic(char_value, char_name):
    status = 'OFF'
    if pe.OPTIONAL_HEADER.DllCharacteristics & char_value != 0:
        status = 'ON'

    print(char_name + ': ' + status)

get_characteristic(DYNAMIC_BASE, "DYNAMIC_BASE")
get_characteristic(FORCE_INTEGRITY, "FORCE_INTEGRITY")
get_characteristic(NX_COMPAT, "NX_COMPAT")

