#pragma once
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <iostream>

using namespace std;

class paillier_public_key
{
    BIGNUM *n, *n2, *g;

public:
    // 构造函数
    paillier_public_key()
    {
        n = BN_new();
        n2 = BN_new();
        g = BN_new();
    }

    // 析构函数
    ~paillier_public_key()
    {
        BN_free(n);
        BN_free(n2);
        BN_free(g);
    }

    // set_n函数
    void set_n(const BIGNUM *n_)
    {
        BN_copy(n, n_);
        // 计算n2
        BN_sqr(n2, n, BN_CTX_new());
    }

    void set_g(const BIGNUM *g_)
    {
        BN_copy(g, g_);
    }

    BIGNUM *get_n() const
    {
        return n;
    }

    BIGNUM *get_n2() const
    {
        return n2;
    }

    BIGNUM *get_g() const
    {
        return g;
    }
};

class paillier_private_key
{
    BIGNUM *lambda, *n, *n2, *mu;

public:
    // 构造函数
    paillier_private_key()
    {
        lambda = BN_new();
        n = BN_new();
        n2 = BN_new();
        mu = BN_new();
    }

    // 析构函数
    ~paillier_private_key()
    {
        BN_free(lambda);
        BN_free(n);
        BN_free(n2);
        BN_free(mu);
    }

    // set_lambda函数
    void set_lambda(const BIGNUM *lambda_)
    {
        BN_copy(lambda, lambda_);
    }

    // set_n函数
    void set_n(const BIGNUM *n_)
    {
        BN_copy(n, n_);
        // 计算n2
        BN_sqr(n2, n, BN_CTX_new());
    }

    // set_mu函数
    void set_mu(const BIGNUM *mu_)
    {
        BN_copy(mu, mu_);
    }

    BIGNUM *get_lambda() const
    {
        return lambda;
    }

    BIGNUM *get_n() const
    {
        return n;
    }

    BIGNUM *get_n2() const
    {
        return n2;
    }

    BIGNUM *get_mu() const
    {
        return mu;
    }
};

// 生成密钥对
int generate_keypair(paillier_public_key &pub_key, paillier_private_key &priv_key, unsigned int key_size, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *lambda = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *mu = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    if (!BN_generate_prime_ex(p, key_size / 2, true, NULL, NULL, NULL) ||
        !BN_generate_prime_ex(q, key_size / 2, true, NULL, NULL, NULL))
    {
        BN_free(p);
        BN_free(q);
        BN_free(n);
        BN_free(lambda);
        BN_free(g);
        BN_free(mu);
        BN_free(gcd);
        BN_free(temp1);
        BN_free(temp2);
        BN_CTX_end(ctx);
        return -1; // 生成素数失败
    }

    // Compute n = pq
    BN_mul(n, p, q, ctx);

    // Compute lambda=lcm(p-1, q-1)
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BN_gcd(gcd, p, q, ctx);
    BN_div(lambda, NULL, p, gcd, ctx);
    BN_mul(lambda, lambda, q, ctx);

    // Compute the modular multiplicative inverse mu=(L(g^lambda mod n^2))^-1 mod n
    BN_mod_inverse(mu, lambda, n, ctx);
    if (!mu)
    {
        BN_free(p);
        BN_free(q);
        BN_free(n);
        BN_free(lambda);
        BN_free(g);
        BN_free(mu);
        BN_free(gcd);
        BN_free(temp1);
        BN_free(temp2);
        BN_CTX_end(ctx);
        return -2; // 计算 mu 失败
    }

    // Set public key (n, g=n+1)
    BN_add(g, n, BN_value_one());
    pub_key.set_n(n);
    pub_key.set_g(g);

    // Set private key lambda and mu
    priv_key.set_lambda(lambda);
    priv_key.set_n(n);
    priv_key.set_mu(mu);

    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(lambda);
    BN_free(g);
    BN_free(mu);
    BN_free(gcd);
    BN_free(temp1);
    BN_free(temp2);
    BN_CTX_end(ctx);
    return 0; // 成功
}

// 同态加密
BIGNUM *paillier_encrypt(const BIGNUM *m, const paillier_public_key &pub_key, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *c = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    BN_rand_range(r, pub_key.get_n());
    BN_mod_exp(temp1, pub_key.get_g(), m, pub_key.get_n2(), ctx);
    BN_mod_exp(temp2, r, pub_key.get_n(), pub_key.get_n2(), ctx);
    BN_mod_mul(c, temp1, temp2, pub_key.get_n2(), ctx);

    BN_free(r);
    BN_free(temp1);
    BN_free(temp2);
    BN_CTX_end(ctx);
    return c;
}

// 同态解密
BIGNUM *paillier_decrypt(const BIGNUM *c, const paillier_private_key &priv_key, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *deMasked = BN_new(); // c^(lambda) % n^2
    BIGNUM *power = BN_new();    // (c^(lambda) % n^2 - 1) / n
    BIGNUM *result = BN_new();   // (power * mu) % n

    // 计算 deMasked = (c^(lambda)) % n^2
    BN_mod_exp(deMasked, c, priv_key.get_lambda(), priv_key.get_n2(), ctx);

    // 计算 power = (deMasked-1) / n
    BN_sub_word(deMasked, 1);
    BN_div(power, NULL, deMasked, priv_key.get_n(), ctx);

    // 计算 result = (power * mu) % n
    BN_mod_mul(result, power, priv_key.get_mu(), priv_key.get_n(), ctx);

    BN_free(deMasked);
    BN_free(power);
    BN_CTX_end(ctx);
    return result;
}

// 同态加法
BIGNUM *paillier_add(const BIGNUM *ciphertext1, const BIGNUM *ciphertext2, const paillier_public_key &pub_key, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *result = BN_new();

    // Compute result = ciphertext1*ciphertext2 mod n^2
    BN_mod_mul(result, ciphertext1, ciphertext2, pub_key.get_n2(), ctx);

    BN_CTX_end(ctx);
    return result;
}

// 同态标量乘法
BIGNUM *paillier_mul(const BIGNUM *ciphertext, const BIGNUM *multiplier, const paillier_public_key &pub_key, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *result = BN_new();

    // Compute result = ciphertext^multiplier mod n^2
    BN_mod_exp(result, ciphertext, multiplier, pub_key.get_n2(), ctx);

    BN_CTX_end(ctx);
    return result;
}

int test()
{
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();

    // 生成密钥对
    paillier_public_key pub_key;
    paillier_private_key priv_key;
    BN_CTX *ctx = BN_CTX_new();
    if (generate_keypair(pub_key, priv_key, 1024, ctx))
    {
        return -1;
    }
    // 明文m1加密
    BIGNUM *m1 = BN_new();
    BN_dec2bn(&m1, "11111");
    BIGNUM *c1 = paillier_encrypt(m1, pub_key, ctx);
    // 明文m2加密
    BIGNUM *m2 = BN_new();
    BN_dec2bn(&m2, "88888");
    BIGNUM *c2 = paillier_encrypt(m2, pub_key, ctx);
    // 同态计算m1+m2
    BIGNUM *c_add = paillier_add(c1, c2, pub_key, ctx);
    // 同态计算m1*5
    BIGNUM *multiplier = BN_new();
    BN_dec2bn(&multiplier, "5");
    BIGNUM *c_mul = paillier_mul(c1, multiplier, pub_key, ctx);

    // 密文解密
    BIGNUM *decrypted_m1 = paillier_decrypt(c1, priv_key, ctx);
    BIGNUM *decrypted_m2 = paillier_decrypt(c2, priv_key, ctx);
    BIGNUM *decrypted_add = paillier_decrypt(c_add, priv_key, ctx);
    BIGNUM *decrypted_mul = paillier_decrypt(c_mul, priv_key, ctx);

    printf("m1=%s\n", BN_bn2dec(decrypted_m1));
    printf("m2=%s\n", BN_bn2dec(decrypted_m2));
    printf("m1+m2=%s\n", BN_bn2dec(decrypted_add));
    printf("m1*%s=%s\n", BN_bn2dec(multiplier), BN_bn2dec(decrypted_mul));

    BN_free(m1);
    BN_free(c1);
    BN_free(m2);
    BN_free(c2);
    BN_free(c_add);
    BN_free(c_mul);
    BN_free(multiplier);
    BN_free(decrypted_m1);
    BN_free(decrypted_m2);
    BN_free(decrypted_add);
    BN_free(decrypted_mul);

    return 0;
}