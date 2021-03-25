@echo off

rem -------------------------------------------------------------
rem  UB data migration command line script for Windows.
rem  This is the bootstrap script for running ubdatamigration console on Windows.
rem -------------------------------------------------------------

@setlocal

set BIN_PATH=%~dp0

if "%PHP_COMMAND%" == "" set PHP_COMMAND=php.exe

%PHP_COMMAND% "%BIN_PATH%ubdatamigration_cli.php" %*

@endlocal