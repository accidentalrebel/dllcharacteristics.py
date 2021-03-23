# dllcharacteristics.py

A simple Python tool for getting and setting the values of DLL characteristics for PE files.

Can quickly set the values for `DYNAMIC_BASE`, `NX_COMPAT`, and `FORCE_INTEGRITY`, but can also be used to set other DLL characteristics found [here](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32).

Inspired by the `setdllcharacteristics` tool by [Didier Stevens](https://blog.didierstevens.com/2010/10/17/setdllcharacteristics/).

## Usage

```console
$ ./dllcharacteristics.py --help
usage: dllcharacteristics.py [-h] [-s name value] [-d [{1,0}]] [-n [{1,0}]] [-f [{1,0}]] [-o OUTPUT] input

A Python tool for getting and setting the values of dll characteristics for PE files.

positional arguments:
  input                 The .exe file to read.

optional arguments:
  -h, --help            show this help message and exit
  -s name value, --set name value
                        Set a specific characteristic name to a value.
  -d [{1,0}], --dynamic_base [{1,0}]
                        Set DYNAMIC_BASE (ASLR) to value on or off.
  -n [{1,0}], --nx_compat [{1,0}]
                        Set NX_COMPAT (DEP) to value on or off.
  -f [{1,0}], --force_integrity [{1,0}]
                        Set FORCE_INTEGRITY (check signaturue) to value on or off.
  -o OUTPUT, --output OUTPUT
                        Output file to write changes to.
```

## Examples
To display all characteristics and whether they are turned on or off:

```console
$ ./dllcharacteristics.py test.exe
Characteristics: 
- 0:  HIGH_ENTROPY_VA
- 1:  DYNAMIC_BASE
- 0:  FORCE_INTEGRITY
- 1:  NX_COMPAT
- 0:  NO_ISOLATION
- 0:  NO_SEH
- 0:  NO_BIND
- 0:  APPCONTAINER
- 0:  WDM_DRIVER
- 0:  GUARD_CF
- 1:  TERMINAL_SERVER_AWARE
```

To set the value of one specific characteristic, and then save the changes:

```console
$ ./dllcharacteristics.py -s NO_BIND 1 -o output.exe test.exe
[INFO] Setting characteristic for NO_BIND to 1
[INFO] Writing to output.exe
```

`DYNAMIC_BASE`, `NX_COMPAT`, and `FORCE_INTEGRITY` have their own dedicated argument options that can be specified for quick use.

```console
$ ./dllcharacteristics.py -d 0 -f 1 -n 0 -o output.exe test.exe
[INFO] Setting characteristic for DYNAMIC_BASE to 0
[INFO] Setting characteristic for NX_COMPAT to 0
[INFO] Setting characteristic for FORCE_INTEGRITY to 1
[INFO] Writing to output.exe
```

## Contributing

Feel free to submit a pull request if you want to improve this tool!
