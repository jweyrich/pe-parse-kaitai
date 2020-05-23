#!/bin/bash
/usr/bin/patch -p 1 ./lib/kaitai/kaitai/kaitaistream.cpp < ./fix-kaitai.patch
