echo off
cls
echo IMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMM;
echo :                                                         º
echo :   Sample file for starting DOSamatic when DOS system    :
echo :   disk is in drive A and DOSamatic Disk is in drive B   :
echo º                                                         :
echo HMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMM<
echo .
echo ÉMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMM;
echo :                                                         :
echo :   Assumes Compaq system with Monochrome Graphics Screen º
echo :                                                         :
echo HÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍMMMMÍM<
echo .
pause
set comspec=A:\COMMAND.COM
set DSH=B:\DOSAMATC.HLP
set DSD=A:\DEBUG.COM
set DSE=A:\EDLIN.COM
set DSV=MONO
DOSAMATC
