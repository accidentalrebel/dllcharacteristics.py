#!/usr/bin/python3

import pefile
from argparse import ArgumentParser

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100


pe = pefile.PE('test.exe')

def get_characteristic(char_value):
    status = 'OFF'
    if pe.OPTIONAL_HEADER.DllCharacteristics & char_value != 0:
        status = 'ON'

    return status

def set_characteristic(char_value, status):
    if status:
        pe.OPTIONAL_HEADER.DllCharacteristics |= char_value
    else:
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~char_value

def get_all_characteristics():
    print('DYNAMIC_BASE: ' + get_characteristic(DYNAMIC_BASE))
    print('FORCE_INTEGRITY: '+ get_characteristic(FORCE_INTEGRITY))
    print('NX_COMPAT: ' + get_characteristic(NX_COMPAT))

def handle_characteristic(characteristic, arg_value):
    if arg_value == None:
        print(get_characteristic(characteristic))
    elif arg_value == '1':
        print('Setting to on...')
        set_characteristic(characteristic, True)
    elif arg_value == '0':
        print('Setting to off...')
        set_characteristic(characteristic, False)

def main():
    parser = ArgumentParser(description='Gets or sets DLL characteristics of PE files.')
    parser.add_argument('-d',
                        '--dynamicbase',
                        choices={'0', '1'},
                        nargs='?',
                        default='default',
                        action='store',
	                help='Set DYNAMIC_BASE (ASLR) to value on or off. Displays current value if no parameter is specified.')
    parser.add_argument('-n',
                        '--nxcompat',
                        choices={'0', '1'},
                        nargs='?',
                        default='default',
                        action='store',
	                help='Set NX_COMPAT (DEP) to value on or off. Displays current value if no parameter is specified.')
    parser.add_argument('-f',
                        '--forceintegrity',
                        choices={'0', '1'},
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

    get_all_characteristics()

    if args.dynamicbase != 'default':
        handle_characteristic(DYNAMIC_BASE, args.dynamicbase)
    elif  args.nxcompat != 'default':
        handle_characteristic(NX_COMPAT, args.nxcompat)
    elif args.forceintegrity != 'default':
        handle_characteristic(FORCE_INTEGRITY, args.forceintegrity)
    elif args.all:
        get_all_characteristics()

    get_all_characteristics()

if __name__ == '__main__':
    main()
