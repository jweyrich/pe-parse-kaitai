#!/bin/bash
pushd ./lib/kaitai
#git checkout 0.7
popd
/usr/bin/patch -p 1 ./lib/kaitai/kaitai/kaitaistream.cpp < ./fix-kaitai.patch
