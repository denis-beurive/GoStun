@ECHO OFF

REM This script sets the environment variable for a given "GO" project.
REM
REM Usage:
REM   Copy this script at the top level directory of the project.
REM   Open the MSDOS window you will use to compile the project.
REM   Then run this script.
REM 
REM Copyright (C) 2012 Denis BEURIVE
REM 
REM This program is free software: you can redistribute it and/or modify
REM it under the terms of the GNU General Public License as published by
REM the Free Software Foundation, either version 3 of the License, or
REM (at your option) any later version.
REM 
REM This program is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
REM GNU General Public License for more details.
REM 
REM You should have received a copy of the GNU General Public License
REM along with this program. If not, see <http://www.gnu.org/licenses/>

REM Make sure that the command GO.EXE is in the PATH.
SET Found=FALSE
FOR %%i IN (%PATH%) DO IF EXIST %%i.\GO.EXE SET Found=TRUE
IF "%Found%" == "TRUE" GOTO goexefound 
  ECHO ERROR: Command GO.EXE was *NOT* found in PATH.
  ECHO Please set the PATH environment variable so that it contains the directory the "GO.EXE" command.
  goto error
:goexefound


REM What is the directory the present batch file being executed in?
SET PWD=%~dp0

REM Make sure that the environment variable GOPATH points to the project's top level directory.
echo Make sure that the environment variable GOPATH points to the project's top level directory.
echo Setting GOPATH to %PWD%.
SET GOPATH=%PWD%

REM Check that the environment variable GOOS is *NOT* set.
IF "%GOOS%" == "" GOTO :endif
   ECHO WARNING: Environment variable GOOS is set (%GOOS%)! Unset it.
   SET GOOS=
:endif

REM Check that the environment variable GOARCH is *NOT* set.
IF "%GOARCH%" == "" GOTO :endif
   ECHO WARNING: Environment variable GOARCH is set (%GOARCH%)! Unset it.
   SET GOARCH=
:endif

REM Check that the environment variable GOROOT is set.
IF NOT "%GOROOT%" == "" GOTO :endif
   ECHO ERROR: Environment variable GOROOT is not set!.
   ECHO Please set this environment variable to the top level directory of the GO installation.
   goto error
:endif

REM By default, the command "go install <package name>" will install programs into the directory "GOPATH/bin".
REM That's what we want. Therefore, check that the environment variable GOBIN is not set.
IF "%GOBIN%" == "" GOTO :endif
   ECHO WARNING: Environment variable GOBIN is set (%GOBIN%))! Unset it.
   SET GOBIN=
:endif

ECHO.
ECHO OK
GOTO final

:error
ECHO.
ECHO An error occurred while checking environment variables.
EXIT /B 1

:final

