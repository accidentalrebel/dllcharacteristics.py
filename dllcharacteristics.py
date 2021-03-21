#!/usr/bin/python3

import pefile
from argparse import ArgumentParser

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100


pe = pefile.PE('test.exe')

def get_characteristic(char_value, char_name):
    status = 'OFF'
    if pe.OPTIONAL_HEADER.DllCharacteristics & char_value != 0:
        status = 'ON'

    print(char_name + ': ' + status)

def get_all_characteristics():
    get_characteristic(DYNAMIC_BASE, "DYNAMIC_BASE")
    get_characteristic(FORCE_INTEGRITY, "FORCE_INTEGRITY")
    get_characteristic(NX_COMPAT, "NX_COMPAT")

def handle_characteristic(characteristic):
    print('handle')

def main():
    parser = ArgumentParser(description='Gets or sets DLL characteristics of PE files.')
    parser.add_argument('-d',
                        '--dynamicbase',
                        choices={'on' ,'off'},
                        nargs='?',
                        default='default',
                        action='store',
	                help='Set DYNAMIC_BASE (ASLR) to value on or off. Displays current value if no parameter is specified.')
    parser.add_argument('-n',
                        '--nxcompat',
                        choices={'on' ,'off'},
                        nargs='?',
                        default='default',
                        action='store',
	                help='Set NX_COMPAT (DEP) to value on or off. Displays current value if no parameter is specified.')
    parser.add_argument('-f',
                        '--forceintegrity',
                        choices={'on' ,'off'},
                        default='default',
                        nargs='?',
                        action='store',
	                help='Set FORCE_INTEGRITY (check signaturue) to value on or off. Displays current value if no parameter is specified.')
    parser.add_argument('-a',
                        '--all',
                        action='store_true',
	                help='Displayt he values of all DLL characteristics.')

    args = parser.parse_args()
    print(args)

    if args.dynamicbase:
        handle_characteristic(DYNAMIC_BASE)
    elif args.nxcompat:
        handle_characteristic(NX_COMPAT)
    elif args.forceintegrity:
        handle_characteristic(FORCE_INTEGRITY)
    elif args.all:
        get_all_characteristics()

if __name__ == '__main__':
    main()
