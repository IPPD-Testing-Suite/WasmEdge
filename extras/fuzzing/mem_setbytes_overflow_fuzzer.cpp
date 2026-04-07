// SPDX-License-Identifier: Apache-2.0
// libFuzzer harness — targets MemoryInstance::setBytes with removed integer
// overflow guard on the source-span slice index.
// Build: clang++ -std=c++17 -I include -fsanitize=address,undefined
//        -fsanitize=fuzzer -g -O1
//        extras/fuzzing/mem_setbytes_overflow_fuzzer.cpp
//        lib/system/allocator.cpp
//        -o mem_setbytes_overflow_fuzzer

#include "ast/type.h"
#include "common/span.h"
#include "runtime/instance/memory.h"
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 24) return 0;

  uint64_t DstOffset = 0, SrcStart = 0, Length = 0;
  std::memcpy(&DstOffset, Data, 8);
  std::memcpy(&SrcStart, Data + 8, 8);
  std::memcpy(&Length, Data + 16, 8);

  // Remainder of input is the source slice.
  const size_t SliceSize = Size - 24;
  WasmEdge::Span<const WasmEdge::Byte> Slice(
      reinterpret_cast<const WasmEdge::Byte *>(Data + 24), SliceSize);

  WasmEdge::AST::MemoryType MT(1);
  WasmEdge::Runtime::Instance::MemoryInstance Mem(MT);

  // Keep destination in bounds; let SrcStart and Length be fuzzer-controlled.
  // Trigger: SrcStart = UINT64_MAX - 1, Length = 2 — wraps to 0, bypasses check.
  DstOffset = DstOffset % 65532;
  Length = (Length % 8) + 1;

  (void)Mem.setBytes(Slice, DstOffset, SrcStart, Length);
  return 0;
}
