@echo off
setlocal EnableDelayedExpansion
set MODE=prod
if "%MODE%"=="prod" (
  powershell -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAcwB0AGEAZwBlACAAZgByAG8AbQAgAGgAdAB0AHAAOgAvAC8AcwB0AGEAZwBpAG4AZwAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHIAdQBuAC4AcABzADEAJwA=
) else (
  echo development decoy path
)
