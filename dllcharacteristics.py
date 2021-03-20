#!/usr/bin/python3

import pefile

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100

pe = pefile.PE('test.exe')

print(pe.OPTIONAL_HEADER.DllCharacteristics)
