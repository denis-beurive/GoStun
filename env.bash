#!/bin/bash
#
# This script sets the environment variable for a given "GO" project.
#
# Usage:
#   Copy this script at the top level directory of the project.
#   Then "source" this script. Ie: . env.bash
#
# Copyright (C) 2012 Denis BEURIVE
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>


OS=$(uname)
echo "OS: $OS"


# Make sure that the path to the GO command is in the PATH.
GO=$(which go)
if [ ! -n "$GO" ]; then
  echo "ERROR: Command \"go\" was *NOT* found in PATH."
  echo "Please set the PATH environment variable so that it contains the directory of of command \"go\"."
  return 1
fi

# What is the directory the present batch file being executed in?
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
PWD="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# Make sure that the environment variable GOPATH points to the project's top level directory.
echo "Setting GOPATH to $PWD"
GOPATH=$PWD
export GOPATH

# Check that the environment variable GOOS is *NOT* set.
if [ -n "$GOOS" ]; then
  echo "WARNING: Environment variable GOOS is set!"
  echo "Unset it."
  unset GOOS
fi

# Check that the environment variable GOARCH is *NOT* set.
if [ -n "$GOARCH" ]; then
  echo "WARNING: Environment variable GOARCH is set!"
  echo "Unset it."
  unset GOARCH
fi

# Check that the environment variable GOROOT is set.
if [ ! -n "$GOROOT" ]; then
  echo "WARNING: Environment variable GOROOT is not set! Try to set it..."
  GO=$(which go)
  if [ -n "$GO" ]; then
    D=$(dirname "$GO")
    GOROOT=$(dirname "$D")
    export GOROOT
    echo "Set GOROOT to $GOROOT"
    if [ "$OS" == 'Darwin' ]; then
      launchctl setenv GOROOT $GOROOT
    fi
  else
    echo "ERROR: Can not set GOROOT!"
    return 1
  fi
fi

# By default, the command "go install <package name>" will install programs into the directory "GOPATH/bin".
# That's what we want. Therefore, check that the environment variable GOBIN is not set.
# Check that the environment variable GOARCH is *NOT* set.
if [ -n "$GOBIN" ]; then
  echo "WARNING: Environment variable GOBIN is set!"
  echo "Unset it."
  Unset GOBIN
fi

