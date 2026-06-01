@echo off
setlocal EnableExtensions EnableDelayedExpansion

set NAME=hello world
set "QUOTED_NAME=hello world"
set NUM=42
set /a SUM=NUM + 8
set /a PROD=NUM * 3
set /a BITAND=255 ^& 15
set /a BITOR=12 ^| 10
set /a BITXOR=12 ^^ 10
set /a SHIFTED=1 ^<^< 4

set COUNT=0
for %%i in (a b c d e) do (
    set /a COUNT+=1
    echo Normal:  %%i index %COUNT%
    echo Delayed: %%i index !COUNT!
)

set THIS_SCRIPT_RAW=%~0
set THIS_SCRIPT_NOQUOTE=%~f0
set THIS_DRIVE=%~d0
set THIS_PATH=%~p0
set THIS_NAME=%~n0
set THIS_EXT=%~x0
set THIS_DRIVEPATH=%~dp0
set THIS_SHORT=%~s0
set THIS_ATTRS=%~a0
set THIS_MTIME=%~t0
set THIS_SIZE=%~z0
set THIS_FULL_AND_QUOTES=%~fnx0

set SRC=The quick brown fox jumps over the lazy dog
set FIRST10=!SRC:~0,10!
set LAST5=!SRC:~-5!
set MID=!SRC:~10,15!
set REPLACE_ALL=!SRC:o=0!
set REMOVE_THE=!SRC:the=!
set UPPER_HINT=!SRC: =_!

if exist "%~dp0\nonexistent.txt" (
    echo found
) else (
    echo missing
)
if defined NAME (
    echo NAME is %NAME%
) else (
    echo NAME is undefined
)
ver >nul 2>&1
if errorlevel 1 (
    echo ver failed
) else (
    echo ver ok
)
if /i "%NAME%"=="HELLO WORLD" (
    echo case-insensitive equality
)
if "%NUM%" GEQ "10" (
    echo num is at least 10
)

echo first ^&^& echo second-only-if-first-ok
echo first ^|^| echo second-only-if-first-failed

ver >nul && (
    echo ver succeeded
) || (
    echo ver failed
)

set TMPFILE=%TEMP%\bcat_demo.txt
^>"%TMPFILE%" (
    echo one,1
    echo two,2
    echo three,3
)
for /F "usebackq tokens=1,2 delims=," %%A in ("%TMPFILE%") do (
    echo line: name=%%A num=%%B
)

for /F "tokens=*" %%L in ('dir /b "%~dp0" 2^>nul') do (
    echo entry: %%L
)

for /F "skip=1 eol=#" %%X in ("%TMPFILE%") do (
    echo X=%%X
)

for /L %%N in (1,1,5) do (
    echo n=%%N
)

for /D %%D in (%SystemRoot%\*) do (
    echo dir=%%~nxD
)

for /R "%~dp0." %%F in (*.bat) do (
    echo bat=%%~nxF
)

del "%TMPFILE%" >nul 2>&1

goto :MAIN_FLOW

:MAIN_FLOW
call :PRINT_BANNER "edge-cases"
call :ECHO_THREE one two three
call :SUM_TWO 5 7 RESULT
echo SUM_TWO returned: !RESULT!
call :PARSE_OPTS /v /i C:\input.txt /o C:\output.txt
call :CASE_ON_VAR
call :LOOP_BREAK_LABEL
goto :END_OF_SCRIPT

:PRINT_BANNER
echo ============================================
echo  %~1
echo ============================================
exit /b 0

:ECHO_THREE
echo arg1=%~1 arg2=%~2 arg3=%~3
exit /b 0

:SUM_TWO
set /a _r = %~1 + %~2
set %3=!_r!
exit /b 0

:PARSE_OPTS
set VERBOSE=0
set INPUT=
set OUTPUT=
:PARSE_OPTS_LOOP
if "%~1"=="" exit /b 0
if /i "%~1"=="/v" set VERBOSE=1 & shift & goto :PARSE_OPTS_LOOP
if /i "%~1"=="/i" set "INPUT=%~2" & shift & shift & goto :PARSE_OPTS_LOOP
if /i "%~1"=="/o" set "OUTPUT=%~2" & shift & shift & goto :PARSE_OPTS_LOOP
echo unknown option: %~1 1>&2
exit /b 2

:CASE_ON_VAR
set KIND=zip
if /i "%KIND%"=="zip" goto :KIND_ZIP
if /i "%KIND%"=="tar" goto :KIND_TAR
if /i "%KIND%"=="gz" goto :KIND_GZ
goto :KIND_UNKNOWN

:KIND_ZIP
echo handling zip
exit /b 0
:KIND_TAR
echo handling tar
exit /b 0
:KIND_GZ
echo handling gz
exit /b 0
:KIND_UNKNOWN
echo unknown kind: %KIND%
exit /b 1

:LOOP_BREAK_LABEL
set BREAK_AT=3
for /L %%i in (1,1,10) do (
    if %%i GEQ !BREAK_AT! (
        echo breaking at %%i
        goto :LOOP_BREAK_DONE
    )
    echo iter %%i
)
:LOOP_BREAK_DONE
exit /b 0

:NESTED_SCOPE
setlocal EnableDelayedExpansion
set INNER_A=alpha
setlocal
set INNER_B=beta
echo deep INNER_A=!INNER_A! INNER_B=!INNER_B!
endlocal
echo after-endlocal INNER_A=!INNER_A! INNER_B=!INNER_B!
endlocal
exit /b 0

:CMD_WITH_EXIT
exit /b %~1

:CAPTURE_VAR_OUT
for /F "delims=" %%V in ('ver') do set VER_LINE=%%V
echo captured: %VER_LINE%
exit /b 0

:CSET
set /a SCORE=72
if !SCORE! GEQ 90 (
    set GRADE=A
) else if !SCORE! GEQ 80 (
    set GRADE=B
) else if !SCORE! GEQ 70 (
    set GRADE=C
) else if !SCORE! GEQ 60 (
    set GRADE=D
) else (
    set GRADE=F
)
echo grade is !GRADE!
exit /b 0

:SWITCH_FRUIT
set FRUIT=apple
2>nul call :SWITCH_FRUIT_%FRUIT%
if errorlevel 1 call :SWITCH_FRUIT_default
exit /b 0
:SWITCH_FRUIT_apple
echo red
exit /b 0
:SWITCH_FRUIT_banana
echo yellow
exit /b 0
:SWITCH_FRUIT_default
echo unknown fruit %FRUIT%
exit /b 0

:PATH_MANIP
set FULL=C:\Users\sample\Documents\report.docx
for %%P in ("%FULL%") do (
    echo drive=%%~dP
    echo path=%%~pP
    echo name=%%~nP
    echo ext=%%~xP
    echo dp=%%~dpP
    echo fnx=%%~fnxP
)
exit /b 0

:DATETIME
for /F "tokens=2-4 delims=/ " %%a in ('date /t') do (
    set CUR_MONTH=%%a
    set CUR_DAY=%%b
    set CUR_YEAR=%%c
)
for /F "tokens=1,2 delims=:." %%a in ('echo %TIME%') do (
    set CUR_HOUR=%%a
    set CUR_MIN=%%b
)
echo %CUR_YEAR%-%CUR_MONTH%-%CUR_DAY% %CUR_HOUR%:%CUR_MIN%
exit /b 0

:RANDOM_USE
echo random1=%RANDOM%
echo random2=%RANDOM%
set "RANDFILE=%TEMP%\rand_%RANDOM%_%RANDOM%.tmp"
echo using temp file %RANDFILE%
type nul >"%RANDFILE%"
del "%RANDFILE%" >nul 2>&1
exit /b 0

:ENV_DUMP
set | findstr /b /i "USER COMPUTERNAME OS PATH " >nul
echo path-length:
echo %PATH% | find /c ";"
exit /b 0

:FILE_OPS
set WORKDIR=%TEMP%\batch_megafile_%RANDOM%
mkdir "%WORKDIR%" 2>nul
echo content-line-1>"%WORKDIR%\a.txt"
echo content-line-2>>"%WORKDIR%\a.txt"
copy /Y "%WORKDIR%\a.txt" "%WORKDIR%\b.txt" >nul
move /Y "%WORKDIR%\b.txt" "%WORKDIR%\c.txt" >nul
attrib +R "%WORKDIR%\a.txt" >nul
attrib -R "%WORKDIR%\a.txt" >nul
type "%WORKDIR%\c.txt" >nul
del /Q "%WORKDIR%\*.txt" >nul
rmdir "%WORKDIR%" >nul 2>&1
exit /b 0

:PUSHPOP
pushd "%SystemRoot%" >nul 2>&1
echo here=%CD%
popd >nul 2>&1
echo back=%CD%
exit /b 0

:CHOICE_USE
choice /C YNQ /N /M "pick (Y/N/Q):" </nul >nul 2>&1
echo errorlevel after choice=%errorlevel%
exit /b 0

:VISUAL
title edge-cases batch megafile
exit /b 0

:COMMENT_FORMS
echo done
exit /b 0

:CASE_TESTS
set A=Hello
set B=hello
if "%A%"=="%B%" (echo exact match) else (echo exact mismatch)
if /i "%A%"=="%B%" (echo case-insensitive match)
if /i not "%A%"=="goodbye" (echo not equal goodbye)
exit /b 0

:TOKEN_REORDER
for /F "tokens=1,2,3,4 delims=-" %%a in ("2026-05-25-T1640") do (
    echo year=%%a month=%%b day=%%c stamp=%%d
)
for /F "tokens=2-4 delims= " %%a in ("the quick brown fox") do (
    echo w2=%%a w3=%%b w4=%%c
)
for /F "tokens=1*" %%a in ("first the rest of the line") do (
    echo head=%%a tail=%%b
)
exit /b 0

:FINDSTR_REGEX
echo HelloWorld | findstr /R "^[A-Z][a-z]*[A-Z][a-z]*$" >nul && echo matched camelcase
echo 192.168.1.1 | findstr /R /C:"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*" >nul && echo matched ip
findstr /n "rem region" "%~f0" | findstr /v /c:"FINDSTR_REGEX" >nul
exit /b 0

:WHERE_USE
where cmd.exe 2>nul
where /Q powershell.exe
echo ps-found=%errorlevel%
exit /b 0

:SLEEP_SUB
ping -n 2 127.0.0.1 >nul 2>&1
timeout /t 1 /nobreak >nul 2>&1
exit /b 0

:PS_ESCAPE
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Out-Null"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& {Write-Host 'from-batch'}"
exit /b 0

:QUOTING
set "PATH_WITH_SPACES=C:\Program Files\Common Files\Microsoft Shared"
echo path is "!PATH_WITH_SPACES!"
set ESCAPED_AMP=a^&b^&c
echo escaped: %ESCAPED_AMP%
set ESCAPED_PIPE=a^|b
echo escaped: %ESCAPED_PIPE%
exit /b 0

:NUM_EDGE
set /a NEG=-5
set /a ABS_NEG=NEG * -1
set /a MOD=17 %% 5
set /a HEX_LIT=0xCAFE
set /a OCT_LIT=0755
set /a UNDERFLOW=NEG - 2147483640
exit /b 0

:END_OF_SCRIPT
endlocal
exit /b 0
