#!/usr/bin/python3

import pefile
from argparse import ArgumentParser

DYNAMIC_BASE = 0x0040
FORCE_INTEGRITY = 0x0080
NX_COMPAT = 0x0100

pe = None
is_verbose = False

def print_verbose(message):
    if is_verbose:
        print('[INFO] ' + message)

def get_characteristic_by_value(value):
    if value == 0x0040:
        return 'DYNAMIC_BASE'
    elif value == 0x0080:
        return 'FORCE_INTEGRITY'
    elif value == 0x0100:
        return 'NX_COMPAT'
    
def get_characteristic(char_value):
    print_verbose('Getting characteristic for ' + get_characteristic_by_value(char_value))
        
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
    print('Characteristics: ')
    print('- DYNAMIC_BASE: ' + get_characteristic(DYNAMIC_BASE))
    print('- FORCE_INTEGRITY: '+ get_characteristic(FORCE_INTEGRITY))
    print('- NX_COMPAT: ' + get_characteristic(NX_COMPAT))

def handle_characteristic(characteristic, arg_value, output_value):
    if arg_value == None:
        print(get_characteristic(characteristic))
        return
    elif arg_value == '1':
        print('Setting to on...')
        set_characteristic(characteristic, True)
    elif arg_value == '0':
        print('Setting to off...')
        set_characteristic(characteristic, False)

    if output_value:
        print('Output placeholder...')
        pe.write(output_value)

def main():
    global pe
    global is_verbose
    
    parser = ArgumentParser(description='Gets or sets DLL characteristics of PE files.')
    parser.add_argument('input',
                        help='The .exe file to read.')
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
    parser.add_argument('-o',
                        '--output',
                        help='Output file to write changes to.')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Make output more verbose.')

    args = parser.parse_args()
    print(args)

    is_verbose = args.verbose

    pe = pefile.PE(args.input)

    if args.dynamicbase != 'default':
        handle_characteristic(DYNAMIC_BASE, args.dynamicbase, args.output)
    if  args.nxcompat != 'default':
        handle_characteristic(NX_COMPAT, args.nxcompat, args.output)
    if args.forceintegrity != 'default':
        handle_characteristic(FORCE_INTEGRITY, args.forceintegrity, args.output)
    if args.dynamicbase == 'default' and args.nxcompat == 'default' and args.forceintegrity:
        get_all_characteristics()

if __name__ == '__main__':
    main()
