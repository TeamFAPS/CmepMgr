cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(CmepMgr)
set(SELF_NAME "cmep_mgr")
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(${PROJECT_NAME}
  src/main.c
  src/cmep_mgr.c
)

target_link_libraries(${PROJECT_NAME}
  SceCpuForDriver_stub
  SceDebugForDriver_stub
  SceIofilemgrForDriver_stub
  SceSysmemForDriver_stub
  SceSysclibForDriver_stub
  SceSysrootForKernel_stub
  SceSblACMgrForDriver_stub
  SceSblSmCommForKernel_stub
  SceThreadmgrForDriver_stub
)

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_KERNEL__"
)

vita_create_self(${SELF_NAME}.skprx ${PROJECT_NAME}
  CONFIG exports.yml
  UNSAFE
  STRIPPED
  REL_OPTIMIZE
)

vita_create_stubs(stubs ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/exports.yml KERNEL)

install(FILES build/stubs/libCmepMgrForKernel_stub.a
  DESTINATION lib
)

install(FILES src/cmep_mgr.h
  DESTINATION include
)
