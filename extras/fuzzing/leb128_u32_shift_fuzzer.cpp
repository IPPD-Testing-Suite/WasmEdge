// SPDX-License-Identifier: Apache-2.0
// libFuzzer harness — targets FileMgr::readU32 shift-exponent overflow.
// Build: clang++ -std=c++17 -I include -fsanitize=address,undefined
//        -fsanitize=fuzzer -g -O1
//        extras/fuzzing/leb128_u32_shift_fuzzer.cpp
//        lib/loader/filemgr.cpp lib/system/mmap.cpp
//        -o leb128_u32_shift_fuzzer

#include "common/types.h"
#include "loader/filemgr.h"
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) return 0;

  WasmEdge::FileMgr FMgr;
  std::vector<WasmEdge::Byte> Code(Data, Data + Size);
  if (!FMgr.setCode(std::move(Code))) return 0;

  // Decode as many U32 LEB128 values as the input allows.
  while (FMgr.getRemainSize() > 0) {
    if (!FMgr.readU32()) break;
  }
  return 0;
}
