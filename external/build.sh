#!/bin/bash -eu
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export CXXFLAGS="${CXXFLAGS} -Wno-error=invalid-specialization"

cd "$SRC/WasmEdge"
sed -ie 's@core lto native@core native@' cmake/Helper.cmake
cmake -GNinja -Bbuild -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWASMEDGE_FORCE_DISABLE_LTO=ON \
  -DWASMEDGE_BUILD_FUZZING=ON \
  -DWASMEDGE_BUILD_TOOLS=OFF \
  -DWASMEDGE_BUILD_TESTS=OFF \
  -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
  -DCMAKE_C_COMPILER_AR="$(command -v llvm-ar)" \
  -DCMAKE_C_COMPILER_RANLIB="$(command -v llvm-ranlib)" \
  -DCMAKE_CXX_COMPILER_AR="$(command -v llvm-ar)" \
  -DCMAKE_CXX_COMPILER_RANLIB="$(command -v llvm-ranlib)" \
  -DLLVM_DIR="/usr/lib/llvm-12/lib/cmake/llvm" \
  -DLLD_DIR="/usr/lib/llvm-12/lib/cmake/lld" \
  .
ninja -C build

# Copy the WasmEdge shared library to $OUT.
cp -a build/lib/api/libwasmedge*.so* "$OUT"/
patchelf --set-rpath \$ORIGIN "$OUT"/libwasmedge*.so*

# Copy each fuzzing harness to $OUT, fix its rpath, and zip its seed corpus.
HARNESSES=(
  mem_oob_store_fuzzer
  leb128_u64_shift_fuzzer
  mem_fill_oob_fuzzer
  mem_setbytes_overflow_fuzzer
  leb128_u32_shift_fuzzer
)

for harness in "${HARNESSES[@]}"; do
  cp "build/extras/fuzzing/${harness}" "$OUT/"
  patchelf --set-rpath \$ORIGIN "$OUT/${harness}"
done

# Package seed corpora (one zip per harness, named <harness>_seed_corpus.zip).
zip -9 "$OUT/mem_oob_store_fuzzer_seed_corpus.zip"         extras/fuzzing/mem_oob_store_corpus/*
zip -9 "$OUT/leb128_u64_shift_fuzzer_seed_corpus.zip"      extras/fuzzing/leb128_u64_shift_corpus/*
zip -9 "$OUT/mem_fill_oob_fuzzer_seed_corpus.zip"          extras/fuzzing/mem_fill_oob_corpus/*
zip -9 "$OUT/mem_setbytes_overflow_fuzzer_seed_corpus.zip" extras/fuzzing/mem_setbytes_overflow_corpus/*
zip -9 "$OUT/leb128_u32_shift_fuzzer_seed_corpus.zip"      extras/fuzzing/leb128_u32_shift_corpus/*

# Copy LLVM and system shared libraries needed at runtime.
for i in libLLVM-12.so.1 libedit.so.2 libbsd.so.0; do
  cp "/usr/lib/x86_64-linux-gnu/${i}" "$OUT/"
  patchelf --set-rpath \$ORIGIN "$OUT/${i}"
done
