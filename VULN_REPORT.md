# WasmEdge Seeded Vulnerability Report

**Library:** WasmEdge (master branch)
**Branch:** master
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-04-07

> **Note:** These bugs are NOT present in the upstream WasmEdge codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-193 | Off-by-one heap OOB write | `include/runtime/instance/memory.h:108` | ASan heap-buffer-overflow | `storeValue<uint32_t>` at offset 65533 into 1-page memory |
| 2 | CWE-190 | Shift-exponent UB (readU64) | `lib/loader/filemgr.cpp:128` | UBSan shift-exponent | 11-byte all-continuation LEB128 sequence |
| 3 | CWE-119 | Heap OOB write (fillBytes) | `include/runtime/instance/memory.h:183` | ASan heap-buffer-overflow | `fillBytes` offset=65536, length=1 |
| 4 | CWE-190 | Integer overflow → OOB read (setBytes) | `include/runtime/instance/memory.h:167` | ASan heap-buffer-overflow | `setBytes` with SrcStart=UINT64\_MAX-1, Length=2 |
| 5 | CWE-190 | Shift-exponent UB (readU32) | `lib/loader/filemgr.cpp:99` | UBSan shift-exponent | 6-byte all-continuation LEB128 sequence |

---

## Bug 1 — Off-by-one in `checkAccessBound`

**File:** `include/runtime/instance/memory.h`, line 108
**Harness:** `extras/fuzzing/mem_oob_store_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
- Offset + Length <= Limit;
+ Offset + Length <= Limit + 1;
```

### Description

`checkAccessBound` computes `Limit = getMin() * kPageSize` (e.g., 65536 for a
1-page memory) and returns `true` when `Offset + Length <= Limit`. The backing
buffer `DataPtr` is allocated for exactly `Limit` bytes, so the last valid byte
is at index `Limit - 1`. By changing the comparison to `<= Limit + 1`, the
check now permits accesses where `Offset + Length == Limit + 1`, meaning the
last byte of the access falls one byte past the end of the allocation. Any
`storeValue`, `loadValue`, `setArray`, or `getArray` call that hits this boundary
will read or write one byte beyond the heap allocation, triggering an ASan
heap-buffer-overflow.

### Trigger Input

```
Offset = 65533, Length = 4 (uint32_t store), 1-page memory
```

`65533 + 4 = 65537 <= 65537` — the modified check passes; `DataPtr[65536]` is
written one byte past the 65536-byte allocation.

### Reproduction

```bash
# Harness constrains Offset to 65531..65536; seed drives it to boundary:
printf '\xfd\xff\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41' | ./mem_oob_store_fuzzer
# Offset = 0xFFFD = 65533; val = 0x41414141
```

---

## Bug 2 — Shift-exponent overflow in `readU64`

**File:** `lib/loader/filemgr.cpp`, line 128
**Harness:** `extras/fuzzing/leb128_u64_shift_fuzzer.cpp`
**Sanitizer:** UBSan shift-exponent

### Change

```diff
- if (unlikely(Offset >= 64)) {
+ if (unlikely(Offset >= 71)) {
```

### Description

`readU64` decodes a variable-length LEB128 unsigned 64-bit integer. It
accumulates bits by shifting each 7-bit payload into `Result` using
`(Byte & UINT64_C(0x7F)) << Offset`, then increments `Offset` by 7. The guard
`Offset >= 64` was intended to reject any encoding that would require shifting
by 64 or more, since shifting a `uint64_t` by ≥ 64 is undefined behavior under
the C++ standard. Raising the limit to `>= 71` permits a 11th continuation
byte (Offset = 70 at time of use), causing a shift of 70 on a 64-bit value —
undefined behavior detected by UBSan as a shift-exponent violation.

### Trigger Input

```
\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00
```

Ten continuation bytes (high bit set) followed by a terminal zero byte. The
loop reaches Offset = 70 before the 11th byte is processed; the guard
`70 >= 71` is false (with the bug), so the shift `0x00 << 70` executes — UB.

### Reproduction

```bash
printf '\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00' | ./leb128_u64_shift_fuzzer
```

---

## Bug 3 — Missing bounds check in `fillBytes`

**File:** `include/runtime/instance/memory.h`, lines 187–191 (deleted)
**Harness:** `extras/fuzzing/mem_fill_oob_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
- if (unlikely(!checkAccessBound(Offset, Length))) {
-   spdlog::error(ErrCode::Value::MemoryOutOfBounds);
-   spdlog::error(ErrInfo::InfoBoundary(Offset, Length, getSize()));
-   return Unexpect(ErrCode::Value::MemoryOutOfBounds);
- }
```

### Description

`fillBytes` is responsible for setting a contiguous range of Wasm memory bytes
to a constant value. The deleted guard called `checkAccessBound(Offset, Length)`
before delegating to `std::fill`. Without this check, any caller-supplied
`Offset` and `Length` values are used directly to compute
`DataPtr + Offset` and `DataPtr + Offset + Length` as the fill range. When
`Offset + Length` exceeds the allocated buffer size, `std::fill` writes past
the end of the heap allocation. Because `fillBytes` is called from the
`memory.fill` Wasm instruction executor, a crafted Wasm module can reach this
path with attacker-controlled operands.

### Trigger Input

```
Offset = 65536, Length = 1, Val = 0x41
```

The allocation is 65536 bytes (indices 0–65535). Writing at `DataPtr[65536]`
is one byte past the end, detected by ASan as a heap-buffer-overflow.

### Reproduction

```bash
# Seed bytes: offset=65536 (0x10000 LE uint64), length=1, val=0x41
printf '\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x41' | ./mem_fill_oob_fuzzer
```

---

## Bug 4 — Integer overflow bypass in `setBytes` source-slice check

**File:** `include/runtime/instance/memory.h`, line 167
**Harness:** `extras/fuzzing/mem_setbytes_overflow_fuzzer.cpp`
**Sanitizer:** ASan heap-buffer-overflow

### Change

```diff
- if (unlikely(std::numeric_limits<uint64_t>::max() - Start < Length ||
-              Start + Length > static_cast<uint64_t>(Slice.size()))) {
+ if (unlikely(Start + Length > static_cast<uint64_t>(Slice.size()))) {
```

### Description

`setBytes` copies `Slice[Start .. Start+Length-1]` into Wasm linear memory.
Before the copy it validated the source range with two sub-conditions: an
overflow guard (`UINT64_MAX - Start < Length`) that detects when
`Start + Length` wraps around, followed by the actual bounds check
(`Start + Length > Slice.size()`). The removed overflow guard means that when
`Start` is near `UINT64_MAX` and `Length` is small, `Start + Length` wraps to
a small value that passes the remaining bounds check. The subsequent
`std::copy` call then evaluates `Slice.begin() + Start`, advancing the source
iterator far past the end of the slice, producing an out-of-bounds read into
unmapped or unrelated heap memory.

### Trigger Input

```
SrcStart = 0xFFFFFFFFFFFFFFFE (UINT64_MAX - 1), Length = 2,
DstOffset = 0, Slice = any 4-byte buffer
```

`(UINT64_MAX - 1) + 2 = 0` (wraps), and `0 <= 4` passes the lone check.
`Slice.begin() + (UINT64_MAX - 1)` is an enormous pointer — heap OOB read.

### Reproduction

```bash
# DstOffset=0 (8B), SrcStart=0xFFFFFFFFFFFFFFFE (8B), Length=2 (8B), data=AAAA (4B)
printf '\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41' \
  | ./mem_setbytes_overflow_fuzzer
```

---

## Bug 5 — Shift-exponent overflow in `readU32`

**File:** `lib/loader/filemgr.cpp`, line 99
**Harness:** `extras/fuzzing/leb128_u32_shift_fuzzer.cpp`
**Sanitizer:** UBSan shift-exponent

### Change

```diff
- if (unlikely(Offset >= 32)) {
+ if (unlikely(Offset >= 39)) {
```

### Description

`readU32` decodes a LEB128 unsigned 32-bit integer by accumulating 7-bit
payloads: `Result |= (Byte & UINT32_C(0x7F)) << Offset`, incrementing
`Offset` by 7 each iteration. The original guard `Offset >= 32` prevented
processing a 6th byte (which would require shifting by 35 into a `uint32_t`).
Raising the threshold to `>= 39` permits that 6th byte: at Offset = 35, the
expression `(Byte & UINT32_C(0x7F)) << 35` shifts a `uint32_t` by 35 bits —
undefined behavior, since the shift count must be less than the bit-width (32).
UBSan reports this as a shift-exponent violation.

### Trigger Input

```
\x80\x80\x80\x80\x80\x00
```

Five continuation bytes (high bit set) followed by a terminal zero. At the
sixth byte Offset = 35; the guard `35 >= 39` is false (with the bug), so
`(0x00 & 0x7F) << 35` executes on a `uint32_t` — UB.

### Reproduction

```bash
printf '\x80\x80\x80\x80\x80\x00' | ./leb128_u32_shift_fuzzer
```

---

## Build Instructions

The harnesses integrate with WasmEdge's existing CMake build system via the
`WASMEDGE_BUILD_FUZZING` flag, exactly like the existing `tools/fuzz/` targets.

### Local build (standalone libFuzzer — no OSS-Fuzz)

```bash
cd /path/to/WasmEdge
mkdir build && cd build

cmake .. \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DWASMEDGE_BUILD_FUZZING=ON \
  -DWASMEDGE_BUILD_TOOLS=OFF \
  -DWASMEDGE_BUILD_TESTS=OFF \
  -DCMAKE_BUILD_TYPE=Debug

make -j$(nproc) \
  mem_oob_store_fuzzer \
  leb128_u64_shift_fuzzer \
  mem_fill_oob_fuzzer \
  mem_setbytes_overflow_fuzzer \
  leb128_u32_shift_fuzzer
```

When `WASMEDGE_BUILD_FUZZING=ON` and `LIB_FUZZING_ENGINE` is **not** set,
[cmake/Helper.cmake](cmake/Helper.cmake) (via `wasmedge_setup_target`) automatically
appends `-fsanitize=fuzzer,address` to every target's compile and link flags.

### OSS-Fuzz build

OSS-Fuzz sets `LIB_FUZZING_ENGINE` to its own engine object (e.g.
`/usr/lib/libFuzzingEngine.a`). Each target in
[extras/fuzzing/CMakeLists.txt](extras/fuzzing/CMakeLists.txt) links it via:

```cmake
if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(<target> PRIVATE ${LIB_FUZZING_ENGINE})
endif()
```

The standard OSS-Fuzz `build.sh` invocation therefore works unchanged:

```bash
cmake $SRC/WasmEdge \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DWASMEDGE_BUILD_FUZZING=ON \
  -DWASMEDGE_BUILD_TOOLS=OFF \
  -DWASMEDGE_BUILD_TESTS=OFF \
  -DLIB_FUZZING_ENGINE=$LIB_FUZZING_ENGINE

make -j$(nproc) \
  mem_oob_store_fuzzer \
  leb128_u64_shift_fuzzer \
  mem_fill_oob_fuzzer \
  mem_setbytes_overflow_fuzzer \
  leb128_u32_shift_fuzzer

cp mem_oob_store_fuzzer        $OUT/
cp leb128_u64_shift_fuzzer     $OUT/
cp mem_fill_oob_fuzzer         $OUT/
cp mem_setbytes_overflow_fuzzer $OUT/
cp leb128_u32_shift_fuzzer     $OUT/
```

### Running with the seed corpus

```bash
# Run with seed corpus (60-second campaign):
./mem_oob_store_fuzzer ../extras/fuzzing/mem_oob_store_corpus/ -max_total_time=60

# Reproduce a known trigger:
printf '\xfd\xff\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41' | ./mem_oob_store_fuzzer
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `mem_oob_store_fuzzer` | Bug 1 |
| `leb128_u64_shift_fuzzer` | Bug 2 |
| `mem_fill_oob_fuzzer` | Bug 3 |
| `mem_setbytes_overflow_fuzzer` | Bug 4 |
| `leb128_u32_shift_fuzzer` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — ASan heap-buffer-overflow
```
==ASAN: heap-buffer-overflow on address 0x... at pc 0x... bp 0x... sp 0x...
WRITE of size 4 at 0x... thread T0
    #0 ... in WasmEdge::Runtime::Instance::MemoryInstance::storeValue<...>
       include/runtime/instance/memory.h
    #1 ... in LLVMFuzzerTestOneInput
       extras/fuzzing/mem_oob_store_fuzzer.cpp
...
0x... is located 0 bytes after 65536-byte region [0x... 0x...)
```

### Bug 2 — UBSan shift-exponent
```
lib/loader/filemgr.cpp:134: runtime error: shift exponent 70 is too large
for 64-bit type 'uint64_t' (aka 'unsigned long')
```

### Bug 3 — ASan heap-buffer-overflow
```
==ASAN: heap-buffer-overflow on address 0x... at pc 0x... bp 0x... sp 0x...
WRITE of size 1 at 0x... thread T0
    #0 ... in WasmEdge::Runtime::Instance::MemoryInstance::fillBytes
       include/runtime/instance/memory.h
    #1 ... in LLVMFuzzerTestOneInput
       extras/fuzzing/mem_fill_oob_fuzzer.cpp
...
0x... is located 0 bytes after 65536-byte region [0x... 0x...)
```

### Bug 4 — ASan heap-buffer-overflow
```
==ASAN: heap-buffer-overflow on address 0x... at pc 0x... bp 0x... sp 0x...
READ of size 1 at 0x... thread T0
    #0 ... in WasmEdge::Runtime::Instance::MemoryInstance::setBytes
       include/runtime/instance/memory.h
    #1 ... in LLVMFuzzerTestOneInput
       extras/fuzzing/mem_setbytes_overflow_fuzzer.cpp
...
READ at enormous offset past end of heap allocation
```

### Bug 5 — UBSan shift-exponent
```
lib/loader/filemgr.cpp:105: runtime error: shift exponent 35 is too large
for 32-bit type 'uint32_t' (aka 'unsigned int')
```

---

## Build System Integration

### CMakeLists.txt

```cmake
add_fuzzer(mem_oob_store)
add_fuzzer(leb128_u64_shift)
add_fuzzer(mem_fill_oob)
add_fuzzer(mem_setbytes_overflow)
add_fuzzer(leb128_u32_shift)
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/mem_oob_store_fuzzer \
  $(OUT)/mem_oob_store_fuzzer_seed_corpus.zip \
  $(OUT)/mem_oob_store_fuzzer.options \
  $(OUT)/leb128_u64_shift_fuzzer \
  $(OUT)/leb128_u64_shift_fuzzer_seed_corpus.zip \
  $(OUT)/leb128_u64_shift_fuzzer.options \
  $(OUT)/mem_fill_oob_fuzzer \
  $(OUT)/mem_fill_oob_fuzzer_seed_corpus.zip \
  $(OUT)/mem_fill_oob_fuzzer.options \
  $(OUT)/mem_setbytes_overflow_fuzzer \
  $(OUT)/mem_setbytes_overflow_fuzzer_seed_corpus.zip \
  $(OUT)/mem_setbytes_overflow_fuzzer.options \
  $(OUT)/leb128_u32_shift_fuzzer \
  $(OUT)/leb128_u32_shift_fuzzer_seed_corpus.zip \
  $(OUT)/leb128_u32_shift_fuzzer.options
```

---

## Changelog

### 2026-04-07 — Initial bug injection

Added 5 intentional vulnerabilities to `include/runtime/instance/memory.h` and
`lib/loader/filemgr.cpp`. Created 5 libFuzzer harnesses under `extras/fuzzing/`
and one binary seed per corpus directory.

### 2026-04-07 — Connected harnesses

Added corpus directories (`*_corpus/`) and binary seed files for each harness.
Seeds place the fuzzer near boundary conditions without triggering bugs.

### 2026-04-07 — Seed summary

| Harness | Seed file | Seed bytes (hex) |
|---------|-----------|------------------|
| `mem_oob_store` | `seed1` | `FC FF 00 00 00 00 00 00 41 41 41 41` |
| `leb128_u64_shift` | `seed1` | `80 80 80 80 80 80 80 80 80 01` |
| `mem_fill_oob` | `seed1` | `FE FF 00 00 00 00 00 00 02 00 00 00 00 00 00 00 41` |
| `mem_setbytes_overflow` | `seed1` | `00×8 00×8 04 00 00 00 00 00 00 00 41 41 41 41` |
| `leb128_u32_shift` | `seed1` | `FF FF FF FF 0F` |

---

*This report documents intentional research vulnerabilities.
The upstream WasmEdge library does not contain these bugs.*
