#!/bin/sh
set -eu

zfs -V
make clean build install test
