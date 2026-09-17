@echo off
setlocal EnableDelayedExpansion
set /a PORT=4000+443
set /a SHIFT=1<<3
set /a MASK=0xFF
echo connecting on port !PORT! shift !SHIFT! mask !MASK!
