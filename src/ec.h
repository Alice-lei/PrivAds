#pragma once
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// 生成指定位数的随机BIGNUM
inline BIGNUM *BN_rand(int bits)
{
    BIGNUM *rand = BN_new();
    BN_rand(rand, bits, 0, 0);
    return rand;
}

// 将BIGNUM转换为十六进制字符串
inline std::string BN_to_string(BIGNUM *bn)
{
    char *tmp = BN_bn2hex(bn);
    std::string str(tmp);
    OPENSSL_free(tmp);
    return str;
}

// 将EC_POINT转换为十六进制字符串
inline std::string EC_POINT_to_string(EC_GROUP *curve, EC_POINT *point, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    char *tmp = EC_POINT_point2hex(curve, point, POINT_CONVERSION_COMPRESSED, ctx);
    std::string str(tmp);
    OPENSSL_free(tmp);
    BN_CTX_end(ctx);
    return str;
}

// 将BIGNUM转换为二进制字符串
inline std::string BN_serialize(BIGNUM *bn)
{
    std::string str;
    int len = BN_bn2mpi(bn, nullptr);
    str.resize(len);
    BN_bn2mpi(bn, (unsigned char *)str.data());
    return str;
}

// 将二进制字符串转换为BIGNUM
inline BIGNUM *BN_deserialize(std::string str)
{
    BIGNUM *bn = BN_mpi2bn((unsigned char *)str.data(), str.size(), nullptr);
    return bn;
}

// 将EC_POINT转换为二进制字符串
inline std::string EC_POINT_serialize(EC_GROUP *curve, EC_POINT *point, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    std::string str;
    int len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
    str.resize(len);
    EC_POINT_point2oct(curve, point, POINT_CONVERSION_COMPRESSED, (unsigned char *)str.data(), len, ctx);
    BN_CTX_end(ctx);
    return str;
}

// 将二进制字符串转换为EC_POINT
inline EC_POINT *EC_POINT_deserialize(EC_GROUP *curve, std::string str, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    EC_POINT *point = EC_POINT_new(curve);
    EC_POINT_oct2point(curve, point, (unsigned char *)str.data(), str.size(), ctx);
    BN_CTX_end(ctx);
    return point;
}

// 椭圆曲线点减法
void EC_POINT_sub(EC_GROUP *curve, EC_POINT *r, EC_POINT *a, EC_POINT *b, BN_CTX *ctx)
{
    EC_POINT *temp = EC_POINT_new(curve);
    EC_POINT_copy(temp, b);
    EC_POINT_invert(curve, temp, ctx);
    EC_POINT_add(curve, r, a, temp, ctx);
    EC_POINT_free(temp);
}

// 公开参数组W1
class W1
{
    EC_GROUP *curve;
    EC_POINT *G0, *G1, *G2, *H0, *Ga, *Ha, *pkA;
    BIGNUM *order;

public:
    W1(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);

        // 选择曲线
        curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

        // 生成sk
        EC_KEY *key = EC_KEY_new();
        EC_KEY_set_group(key, curve);
        if (!EC_KEY_generate_key(key))
        {
            std::cerr << "Error generating key" << std::endl;
            return;
        }
        // 获取pk
        const EC_POINT *pk = EC_KEY_get0_public_key(key);

        // 获取order
        order = BN_new();
        EC_GROUP_get_order(curve, order, ctx);

        // 初始化 G0,G1,G2,H0,Ga,Ha,pkA
        G0 = EC_POINT_new(curve);
        G1 = EC_POINT_new(curve);
        G2 = EC_POINT_new(curve);
        H0 = EC_POINT_new(curve);
        Ga = EC_POINT_new(curve);
        Ha = EC_POINT_new(curve);
        pkA = EC_POINT_new(curve);

        // 分别生成随机数计算G0,G1,G2,H0,Ga,Ha
        BIGNUM *r1 = BN_rand(256);
        BIGNUM *r2 = BN_rand(256);
        BIGNUM *r3 = BN_rand(256);
        BIGNUM *r4 = BN_rand(256);
        BIGNUM *r5 = BN_rand(256);
        BIGNUM *r6 = BN_rand(256);
        EC_POINT_mul(curve, G0, NULL, pk, r1, ctx);
        EC_POINT_mul(curve, G1, NULL, pk, r2, ctx);
        EC_POINT_mul(curve, G2, NULL, pk, r3, ctx);
        EC_POINT_mul(curve, H0, NULL, pk, r4, ctx);
        EC_POINT_mul(curve, Ga, NULL, pk, r5, ctx);
        EC_POINT_mul(curve, Ha, NULL, pk, r6, ctx);

        // Clean up
        BN_free(r1);
        BN_free(r2);
        BN_free(r3);
        BN_free(r4);
        BN_free(r5);
        BN_free(r6);
        EC_KEY_free(key);
        BN_CTX_end(ctx);
    }

    // 释放内存
    ~W1()
    {
        EC_POINT_free(G0);
        EC_POINT_free(G1);
        EC_POINT_free(G2);
        EC_POINT_free(H0);
        EC_POINT_free(Ga);
        EC_POINT_free(Ha);
        EC_POINT_free(pkA);
        BN_free(order);
        EC_GROUP_free(curve);
    }

    // 将W1的参数转换为字符串，并清理内存
    std::string to_string(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::stringstream ss;
        char *tmp = EC_POINT_point2hex(curve, G0, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, G1, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, G2, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, H0, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, Ga, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, Ha, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = BN_bn2hex(order);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, pkA, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        BN_CTX_end(ctx);
        return ss.str();
    }

    EC_GROUP *get_curve() const { return curve; }
    EC_POINT *get_G0() const { return G0; }
    EC_POINT *get_G1() const { return G1; }
    EC_POINT *get_G2() const { return G2; }
    EC_POINT *get_H0() const { return H0; }
    EC_POINT *get_Ga() const { return Ga; }
    EC_POINT *get_Ha() const { return Ha; }
    void set_pkA(EC_POINT *pkA) { EC_POINT_copy(this->pkA, pkA); }
    EC_POINT *get_pkA() const { return pkA; }
    BIGNUM *get_order() const { return order; }
};

// 公开参数组P0
class P0
{
    EC_GROUP *curve;
    EC_POINT *W_, *C1_;

public:
    // 构造函数，输入W'和C1'，并赋值
    P0(EC_GROUP *curve, EC_POINT *W_, EC_POINT *C1_) : curve(curve)
    {
        this->W_ = EC_POINT_new(curve);
        this->C1_ = EC_POINT_new(curve);
        EC_POINT_copy(this->W_, W_);
        EC_POINT_copy(this->C1_, C1_);
    }

    // 释放内存
    ~P0()
    {
        EC_POINT_free(W_);
        EC_POINT_free(C1_);
    }

    // 将P0的参数转换为字符串
    std::string to_string(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::stringstream ss;
        char *tmp = EC_POINT_point2hex(curve, W_, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, C1_, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        BN_CTX_end(ctx);
        return ss.str();
    }

    // get函数
    EC_POINT *get_W_() const { return W_; }
    EC_POINT *get_C1_() const { return C1_; }
};

// 公开参数组Pi
class Pi
{
    EC_GROUP *curve;
    EC_POINT *Ai, *Di;

public:
    // 构造函数，输入Ai和Di，赋值
    Pi(EC_GROUP *curve, EC_POINT *Ai, EC_POINT *Di) : curve(curve)
    {
        this->Ai = EC_POINT_new(curve);
        this->Di = EC_POINT_new(curve);
        EC_POINT_copy(this->Ai, Ai);
        EC_POINT_copy(this->Di, Di);
    }

    // 释放内存
    ~Pi()
    {
        EC_POINT_free(Ai);
        EC_POINT_free(Di);
    }

    // 将Pi的参数转换为字符串
    std::string to_string(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::stringstream ss;
        char *tmp = EC_POINT_point2hex(curve, Ai, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, Di, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        BN_CTX_end(ctx);
        return ss.str();
    }

    // get函数
    EC_POINT *get_Ai() const { return Ai; }
    EC_POINT *get_Di() const { return Di; }
};

int ecdhTest()
{
    // 选择曲线
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    // 生成私钥
    EC_KEY *ec_key1 = EC_KEY_new();
    EC_KEY *ec_key2 = EC_KEY_new();
    EC_KEY_set_group(ec_key1, curve);
    EC_KEY_set_group(ec_key2, curve);

    // 生成密钥对
    if (!EC_KEY_generate_key(ec_key1) || !EC_KEY_generate_key(ec_key2))
    {
        printf("Failed to generate EC key pair.\n");
        return 1;
    }

    // 获取公钥
    const EC_POINT *pub_key1 = EC_KEY_get0_public_key(ec_key1);
    const EC_POINT *pub_key2 = EC_KEY_get0_public_key(ec_key2);

    // 计算 s1 = ec_key1 * pub_key2
    EC_POINT *s1 = EC_POINT_new(curve);
    const BIGNUM *priv_key1 = EC_KEY_get0_private_key(ec_key1);
    if (!EC_POINT_mul(curve, s1, priv_key1, pub_key2, NULL, NULL))
    {
        printf("Failed to compute shared secret.\n");
        return 1;
    }

    // 计算 s2 = ec_key2 * pub_key1
    EC_POINT *s2 = EC_POINT_new(curve);
    const BIGNUM *priv_key2 = EC_KEY_get0_private_key(ec_key2);
    if (!EC_POINT_mul(curve, s2, priv_key2, pub_key1, NULL, NULL))
    {
        printf("Failed to compute shared secret.\n");
        return 1;
    }

    // 验证 s1 == s2
    if (!EC_POINT_cmp(curve, s1, s2, NULL))
    {
        printf("ECDH key exchange failed.\n");
        return 1;
    }
    else
    {
        printf("ECDH key exchange succeed.\n");
        // 打印key
        std::cout << "key: " << EC_POINT_point2hex(curve, s1, POINT_CONVERSION_COMPRESSED, NULL) << std::endl;
        std::cout << "key: " << EC_POINT_point2hex(curve, s2, POINT_CONVERSION_COMPRESSED, NULL) << std::endl;
    }

    // 释放资源
    EC_POINT_free(s1);
    EC_POINT_free(s2);
    EC_KEY_free(ec_key1);
    EC_KEY_free(ec_key2);
    EC_GROUP_free(curve);
    return 0;
}