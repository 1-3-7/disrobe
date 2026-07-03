@echo off
setlocal EnableDelayedExpansion
set "Pd94f=hello world"
for /F "tokens=*" %%A in ("!Pd94f!") do echo %%A
