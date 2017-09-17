@echo on
cd C:\fuzz\fuzzer
rmdir /s /q C:\fuzz\fuzzer\av_ioctlFuzzer
git clone https://github.com/pwn2expoit/av_ioctlFuzzer/
copy C:\fuzz\fuzzer\av_ioctlFuzzer\* C:\fuzz\fuzzer\*
pause