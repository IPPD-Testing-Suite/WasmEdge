// SPDX-License-Identifier: Apache-2.0
// libFuzzer harness — targets MemoryInstance::storeValue via checkAccessBound.
// Build: clang++ -std=c++17 -I include -fsanitize=address,undefined
//        -fsanitize=fuzzer -g -O1
//        extras/fuzzing/mem_oob_store_fuzzer.cpp
//        lib/system/allocator.cpp   (or link against wasmedge)
//        -o mem_oob_store_fuzzer

#include "ast/type.h"
#include "runtime/instance/memory.h"
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 12) return 0;

  uint64_t Offset = 0;
  std::memcpy(&Offset, Data, 8);
  uint32_t Val = 0;
  std::memcpy(&Val, Data + 8, 4);

  // Constrain to the boundary zone of a 1-page (65536-byte) memory.
  // Valid 4-byte stores: offsets 0..65532. Trigger offset: 65533.
  Offset = (Offset % 6) + 65531;

  WasmEdge::AST::MemoryType MT(1);
  WasmEdge::Runtime::Instance::MemoryInstance Mem(MT);

  (void)Mem.storeValue<uint32_t>(Val, Offset);
  return 0;
}
