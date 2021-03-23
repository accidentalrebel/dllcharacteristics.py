#!/usr/bin/python3

import pefile
from argparse import ArgumentParser

characteristics = {
    'HIGH_ENTROPY_VA' : 0x0020,
    'DYNAMIC_BASE' : 0x0040,
    'FORCE_INTEGRITY' : 0x0080,
    'NX_COMPAT' : 0x0100,
    'NO_ISOLATION' : 0x0200,
    'NO_SEH' : 0x0400,
    'NO_BIND' : 0x0800,
    'APPCONTAINER' : 0x1000,
    'WDM_DRIVER' : 0x2000,
    'GUARD_CF' : 0x4000,
    'TERMINAL_SERVER_AWARE' : 0x8000
}

def get_characteristic_by_value(value):
    for c in characteristics:
        flag_value = get_flag_value_by_name(c)
        if flag_value == value:
            return c

    print('[ERROR] No characterstic is associated with value ' + value)
    raise SystemExit(1)

def get_flag_value_by_name(name):
    return characteristics[name.upper()]
    
def get_characteristic(pe, char_value):
    status = 0
    if pe.OPTIONAL_HEADER.DllCharacteristics & char_value != 0:
        status = 1

    return status

def set_characteristic(pe, char_value, status):
    if status == 1:
        pe.OPTIONAL_HEADER.DllCharacteristics |= char_value
    elif status == 0:
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~char_value
    else:
        print('[ERROR] Invalid status value. Should be only 0 or 1.')
        raise SystemExit(1)

def get_all_characteristics(pe):
    print('Characteristics: ')
    for c in characteristics:
        value =  get_characteristic(pe, get_flag_value_by_name(c))
            
        print('- ' + str(value) + ':  ' + c)

def handle_characteristic(pe, characteristic, arg_value):
    if arg_value == '1':
        print('[INFO] Setting characteristic for ' + get_characteristic_by_value(characteristic) + ' to ' + str(arg_value))
        set_characteristic(pe, characteristic, True)
    elif arg_value == '0':
        print('[INFO] Setting characteristic for ' + get_characteristic_by_value(characteristic) + ' to ' + str(arg_value))
        set_characteristic(pe, characteristic, False)

def main():
    parser = ArgumentParser(description='A Python tool for getting and setting the values of dll characteristics for PE files.')
    parser.add_argument('input',
                        help='The .exe file to read.')
    parser.add_argument('-s',
                        '--set',
                        nargs=2,
                        metavar=('name','value'),
	                help='Set a specific characteristic name to a value. ')
    parser.add_argument('-d',
                        '--dynamic_base',
                        choices={'0', '1'},
                        nargs='?',
                        action='store',
	                help='Set DYNAMIC_BASE (ASLR) to value on or off.')
    parser.add_argument('-n',
                        '--nx_compat',
                        choices={'0', '1'},
                        nargs='?',
                        action='store',
	                help='Set NX_COMPAT (DEP) to value on or off.')
    parser.add_argument('-f',
                        '--force_integrity',
                        choices={'0', '1'},
                        nargs='?',
                        action='store',
	                help='Set FORCE_INTEGRITY (check signaturue) to value on or off.')
    parser.add_argument('-o',
                        '--output',
                        help='Output file to write changes to.')

    args = parser.parse_args()
    
    pe = pefile.PE(args.input)

    if args.set:
        name, value = args.set
        handle_characteristic(pe, get_flag_value_by_name(name), value)
    if args.dynamic_base:
        handle_characteristic(pe, get_flag_value_by_name('DYNAMIC_BASE'), args.dynamic_base)
    if  args.nx_compat:
        handle_characteristic(pe, get_flag_value_by_name('NX_COMPAT'), args.nx_compat)
    if args.force_integrity:
        handle_characteristic(pe, get_flag_value_by_name('FORCE_INTEGRITY'), args.force_integrity)
    if not args.dynamic_base and not args.nx_compat and not args.force_integrity and not args.set:
        get_all_characteristics(pe)
    else:
        if args.output:
            print('[INFO] Writing to ' + args.output)
            pe.write(args.output)

if __name__ == '__main__':
    main()
