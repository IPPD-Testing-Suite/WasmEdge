// SPDX-License-Identifier: Apache-2.0
// libFuzzer harness — targets MemoryInstance::fillBytes with missing bounds check.
// Build: clang++ -std=c++17 -I include -fsanitize=address,undefined
//        -fsanitize=fuzzer -g -O1
//        extras/fuzzing/mem_fill_oob_fuzzer.cpp
//        lib/system/allocator.cpp
//        -o mem_fill_oob_fuzzer

#include "ast/type.h"
#include "runtime/instance/memory.h"
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 17) return 0;

  uint64_t Offset = 0, Length = 0;
  uint8_t Val = 0;
  std::memcpy(&Offset, Data, 8);
  std::memcpy(&Length, Data + 8, 8);
  Val = Data[16];

  // Constrain offset to straddle the page boundary (65536 bytes).
  // Trigger: Offset=65536, Length=1 — fills 1 byte past end of allocation.
  Offset = (Offset % 4) + 65534;
  Length = (Length % 4) + 1;

  WasmEdge::AST::MemoryType MT(1);
  WasmEdge::Runtime::Instance::MemoryInstance Mem(MT);

  (void)Mem.fillBytes(Val, Offset, Length);
  return 0;
}
