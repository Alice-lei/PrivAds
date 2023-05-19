file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/src/*.c ${CMAKE_SOURCE_DIR}/src/*.cpp )
include_directories(${CMAKE_SOURCE_DIR}/src/)

# 查找Protocol Buffers包
find_package(Protobuf REQUIRED)
# 将.proto文件编译成C++文件
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS messages.proto)

# OpenSSL
find_package(OpenSSL REQUIRED)

# OpenMP
find_package(OpenMP REQUIRED)

ADD_EXECUTABLE(main ${PROTO_SRCS} ${PROTO_HDRS} ${SRC_FRONTEND})

target_include_directories(main
    PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
)

set(DEP_LIBS
    OpenMP::OpenMP_CXX OpenSSL::Crypto OpenSSL::SSL
)

target_link_libraries(main
    PUBLIC
    ${PROTOBUF_LIBRARIES}
    ${DEP_LIBS}
    -pthread
)

