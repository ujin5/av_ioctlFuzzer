# Fuzzer

## IOTCL Fuzzer
1. Immunity debugger에 대상 driver load
2. ` !ioctl_dump`로 PyCommand 실행 (pickle file이 Immunity debugger directory에 저장됨)
3. `python ioctl_fuzzer.py [pickle filename]`


## File Fuzzer
1. Make `examples` and `crashes` directories in the parent directory of the script.
2.  seed files (suitable for fuzzee) in the `examples` directory.
3. `python file_fuzzer.py -e [fuzzee path] -x .[extension for seed files]`
