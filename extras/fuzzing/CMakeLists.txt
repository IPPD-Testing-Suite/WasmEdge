# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2019-2024 Second State INC

# ---------------------------------------------------------------------------
# mem_oob_store_fuzzer — Bug 1: off-by-one in checkAccessBound
# ---------------------------------------------------------------------------
wasmedge_add_executable(mem_oob_store_fuzzer
  mem_oob_store_fuzzer.cpp
)

target_include_directories(mem_oob_store_fuzzer
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(mem_oob_store_fuzzer
  PRIVATE
  wasmedgeSystem
)

if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(mem_oob_store_fuzzer
    PRIVATE
    ${LIB_FUZZING_ENGINE}
  )
endif()

# ---------------------------------------------------------------------------
# leb128_u64_shift_fuzzer — Bug 2: shift-exponent UB in readU64
# ---------------------------------------------------------------------------
wasmedge_add_executable(leb128_u64_shift_fuzzer
  leb128_u64_shift_fuzzer.cpp
)

target_include_directories(leb128_u64_shift_fuzzer
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(leb128_u64_shift_fuzzer
  PRIVATE
  wasmedgeLoaderFileMgr
)

if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(leb128_u64_shift_fuzzer
    PRIVATE
    ${LIB_FUZZING_ENGINE}
  )
endif()

# ---------------------------------------------------------------------------
# mem_fill_oob_fuzzer — Bug 3: missing bounds check in fillBytes
# ---------------------------------------------------------------------------
wasmedge_add_executable(mem_fill_oob_fuzzer
  mem_fill_oob_fuzzer.cpp
)

target_include_directories(mem_fill_oob_fuzzer
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(mem_fill_oob_fuzzer
  PRIVATE
  wasmedgeSystem
)

if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(mem_fill_oob_fuzzer
    PRIVATE
    ${LIB_FUZZING_ENGINE}
  )
endif()

# ---------------------------------------------------------------------------
# mem_setbytes_overflow_fuzzer — Bug 4: integer overflow bypass in setBytes
# ---------------------------------------------------------------------------
wasmedge_add_executable(mem_setbytes_overflow_fuzzer
  mem_setbytes_overflow_fuzzer.cpp
)

target_include_directories(mem_setbytes_overflow_fuzzer
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(mem_setbytes_overflow_fuzzer
  PRIVATE
  wasmedgeSystem
)

if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(mem_setbytes_overflow_fuzzer
    PRIVATE
    ${LIB_FUZZING_ENGINE}
  )
endif()

# ---------------------------------------------------------------------------
# leb128_u32_shift_fuzzer — Bug 5: shift-exponent UB in readU32
# ---------------------------------------------------------------------------
wasmedge_add_executable(leb128_u32_shift_fuzzer
  leb128_u32_shift_fuzzer.cpp
)

target_include_directories(leb128_u32_shift_fuzzer
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(leb128_u32_shift_fuzzer
  PRIVATE
  wasmedgeLoaderFileMgr
)

if(DEFINED LIB_FUZZING_ENGINE)
  target_link_libraries(leb128_u32_shift_fuzzer
    PRIVATE
    ${LIB_FUZZING_ENGINE}
  )
endif()
