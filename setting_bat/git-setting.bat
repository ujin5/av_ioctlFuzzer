@echo on
mkdir C:\fuzz\fuzzer
cd C:\fuzz\fuzzer
rmdir /s /q C:\fuzz\fuzzer\av_ioctlFuzzer
git clone https://github.com/pwn2expoit/av_ioctlFuzzer/
copy C:\fuzz\fuzzer\av_ioctlFuzzer\* C:\fuzz\fuzzer\*
copy C:\fuzz\fuzzer\av_ioctlFuzzer\setting_bat\Start_fuzzer.bat %USERPROFILE%\Start_fuzzer.bat
copy C:\fuzz\fuzzer\av_ioctlFuzzer\setting_bat\start_FFV3.bat %USERPROFILE%\start_FFV3.bat
pause