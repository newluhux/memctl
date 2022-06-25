#!/bin/sh

POS=$(dirname $(realpath $0))
SRC=$(realpath $POS/../)

guix system vm \
     $POS/testvm.scm \
     --no-graphic \
     --expose=$SRC=/src > $POS/vmstart.sh

sh $POS/vmstart.sh
