# dllcharacteristics.py

A simple Python tool for getting and setting the values of dll characteristics for PE files.

Inspired by `setdllcharacteristics` tool by [Didier Stevens](https://blog.didierstevens.com/2010/10/17/setdllcharacteristics/).

## Usage

```
$ ./dllcharacteristics.py test.exe --help
usage: dllcharacteristics.py [-h] [-d [{0,1}]] [-n [{0,1}]] [-f [{0,1}]] [-o OUTPUT] input

A Python tool for getting and setting the values of dll characteristics for PE files.

positional arguments:
  input                 The .exe file to read.

optional arguments:
  -h, --help            show this help message and exit
  -d [{0,1}], --dynamicbase [{0,1}]
                        Set DYNAMIC_BASE (ASLR) to value on or off. Displays current value if no parameter is specified.
  -n [{0,1}], --nxcompat [{0,1}]
                        Set NX_COMPAT (DEP) to value on or off. Displays current value if no parameter is specified.
  -f [{0,1}], --forceintegrity [{0,1}]
                        Set FORCE_INTEGRITY (check signaturue) to value on or off. Displays current value if no parameter is specified.
  -o OUTPUT, --output OUTPUT
                        Output file to write changes to.
```

## Contributing

Feel free to submit a pull request if you want to improve this tool!
