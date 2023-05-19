#pragma once
#include "base.h"

// 计算输入值的哈希值
template <typename... Args>
inline BIGNUM *BN_hash(const Args &...args)
{
    std::string input;
    // C++17 折叠表达式 (fold expression)
    // 初始化 result 为折叠表达式 (((result + args) + ...) + args)
    ((input += args), ...);
    BIGNUM *hash = BN_new();
    unsigned char *out = new unsigned char[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(out, &sha256);
    BN_bin2bn(out, 32, hash);
    delete[] out;
    return hash;
}