#!/usr/bin/python3

import pefile
from argparse import ArgumentParser

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100

parser = ArgumentParser(description='Gets or sets DLL characteristics of PE files.')
parser.add_argument('-d',
                    '--dynamic',
                    choices={'on' ,'off'},
                    nargs='?',
                    action='store',
	            help='Set DYNAMIC_BASE (ASLR) to value on or off. Displays current value if no parameter is specified.')

args = parser.parse_args()
print(args.dynamic)

pe = pefile.PE('test.exe')

def get_characteristic(char_value, char_name):
    status = 'OFF'
    if pe.OPTIONAL_HEADER.DllCharacteristics & char_value != 0:
        status = 'ON'

    print(char_name + ': ' + status)

get_characteristic(DYNAMIC_BASE, "DYNAMIC_BASE")
get_characteristic(FORCE_INTEGRITY, "FORCE_INTEGRITY")
get_characteristic(NX_COMPAT, "NX_COMPAT")

