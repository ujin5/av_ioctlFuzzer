# Fuzzer

## IOTCL Fuzzer
1. Load target driver on Immunity debugger.
2. Issue ` !ioctl_dump` PyCommand (pickle file will be saved in Immunity debugger directory.)
3. `python ioctl_fuzzer.py [pickle filename]`


## File Fuzzer
1. Make `examples` and `crashes` directories in the parent directory of the script.
2. Make seed files (suitable for fuzzee) in the `examples` directory.
3. `python file_fuzzer.py -e [fuzzee path] -x .[extension for seed files]`
