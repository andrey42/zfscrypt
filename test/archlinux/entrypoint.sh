#!/bin/sh
set -eu

zfs -V
# make clean build install test
echo passw0rd | zfs create -o encryption=on -o keyformat=passphrase -o keylocation=prompt tank/test
zfs list
zfs mount
