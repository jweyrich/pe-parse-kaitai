#!/bin/bash
pushd ./src
kaitai-struct-compiler  --target=cpp_stl ./microsoft_pe.ksy
popd