#pragma once
#include "base.h"
#include "ec.h"
#include "hash.h"
#include "Messages.h"

class Advertiser
{
    W1 *w1;
    int user_count_advertiser;
    int user_count_platform;
    BIGNUM *skA, **u = nullptr, **r = nullptr;
    EC_POINT *pkA;
    // 证明Proof
    Proof *proof = nullptr;
    Message_A2 *message_a2 = nullptr;
    Message_A4 *message_a4 = nullptr;
    Message_A4_ *message_a4_ = nullptr;
    std::unordered_map<std::string, std::string> *U_Evidence = nullptr;

    // 共享变量
    BIGNUM *k1 = BN_rand(256);
    EC_POINT **A = nullptr;
    std::unordered_map<std::string, Messages::Msg_ElGamal_ciphertext> *A_V = nullptr;
    BIGNUM *skA_ = nullptr;
    ElGamal_ciphertext **V;
    Message_P1 *message_p1 = nullptr;
    Message_P3 *message_p3 = nullptr;
    Message_P3_ *message_p3_ = nullptr;
    std::string msg_p3_;
    // debug
    EC_POINT *Sum_d = nullptr;

public:
    // 构造函数
    Advertiser(W1 *w1, int user_count_advertiser, int user_count_platform) : w1(w1), user_count_advertiser(user_count_advertiser), user_count_platform(user_count_platform)
    {
        // 生成随机数skA作为私钥
        skA = BN_rand(256);
        // 计算公钥pkA = skA*Ha
        pkA = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), pkA, NULL, w1->get_Ha(), skA, NULL);
        w1->set_pkA(pkA);
    }

    // 析构函数
    ~Advertiser()
    {
        BN_free(skA);
        EC_POINT_free(pkA);
        if (u != nullptr && r != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                BN_free(u[i]);
                BN_free(r[i]);
            }
            delete[] u;
            delete[] r;
        }
        if (proof != nullptr)
            delete proof;
        if (message_p1 != nullptr)
            delete message_p1;
        if (message_a2 != nullptr)
            delete message_a2;
        if (message_p3 != nullptr)
            delete message_p3;
        if (message_a4 != nullptr)
            delete message_a4;
        // 释放k1，A，A_V，skA_，Sum_d
        if (k1 != nullptr)
            BN_free(k1);
        if (A != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                EC_POINT_free(A[i]);
            }
            delete[] A;
        }
        if (A_V != nullptr)
        {
            delete[] A_V;
        }
        if (skA_ != nullptr)
            BN_free(skA_);
    }

    // 计算证明
    void proof_gen(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        this->proof = new Proof();
        proof->user_count_advertiser = user_count_advertiser;

        // 生成随机数k'，x'和y'
        BIGNUM *k_ = BN_rand(256);
        BIGNUM *x_ = BN_rand(256);
        BIGNUM *y_ = BN_rand(256);

        // 选择 n 个随机数 {a1,a2,...,an}，其中n为用户数量
        BIGNUM **a = new BIGNUM *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            a[i] = BN_rand(256);
        }

        // 计算 Ui = ui*G_0 + ri*H0
        proof->U = new EC_POINT *[user_count_advertiser];
        // 计算 Ai = k1*ui*G2
        proof->A = new EC_POINT *[user_count_advertiser];
        // 计算 Di = k1*Ui
        proof->D = new EC_POINT *[user_count_advertiser];
        // 保存向量A
        A = new EC_POINT *[user_count_advertiser];
        // 为Ui, Ai, Di分配空间
        for (int i = 0; i < user_count_advertiser; i++)
        {
            proof->U[i] = EC_POINT_new(w1->get_curve());
            proof->A[i] = EC_POINT_new(w1->get_curve());
            proof->D[i] = EC_POINT_new(w1->get_curve());
            A[i] = EC_POINT_new(w1->get_curve());
        }

        // 计算 U'= a1*U1 + a2*U2 + ... + an*Un
        proof->U_ = EC_POINT_new(w1->get_curve());
        // 赋值 U' = 0
        EC_POINT_set_to_infinity(w1->get_curve(), proof->U_);
        // 计算 x_hat = x' + S1*k1*u1 + S2*k1*u2 + ... + Sn*k1*un
        proof->x_hat = BN_new();
        BN_copy(proof->x_hat, x_); // 将x'赋值给x_hat
        // 计算 y_hat = y' + S1*k1*r1 + S2*k1*r2 + ... + Sn*k1*rn
        proof->y_hat = BN_new();
        BN_copy(proof->y_hat, y_); // 将y'赋值给y_hat

        // 使用unordered_map存储Ai与Vi的关系，并分配在堆上
        A_V = new std::unordered_map<std::string, Messages::Msg_ElGamal_ciphertext>[user_count_advertiser];
        // 循环计算Ui，Ai，Di，U'，x_hat和y_hat
        //初始化V
        V = new ElGamal_ciphertext *[user_count_advertiser];
// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; i++)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 初始化临时变量
            EC_POINT *temp_Ui1 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_Ui2 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_U_ = EC_POINT_new(w1->get_curve());
            BIGNUM *temp = BN_new();
            BIGNUM *temp_x_hat = BN_new();
            BIGNUM *temp_y_hat = BN_new();
            // 计算Ui
            EC_POINT_mul(w1->get_curve(), temp_Ui1, NULL, w1->get_G0(), u[i], temp_ctx);
            EC_POINT_mul(w1->get_curve(), temp_Ui2, NULL, w1->get_H0(), r[i], temp_ctx);
            EC_POINT_add(w1->get_curve(), proof->U[i], temp_Ui1, temp_Ui2, temp_ctx);
            // 计算Ai
            EC_POINT_mul(w1->get_curve(), proof->A[i], NULL, w1->get_G2(), k1, temp_ctx);
            EC_POINT_mul(w1->get_curve(), proof->A[i], NULL, proof->A[i], u[i], temp_ctx);
            EC_POINT_copy(A[i], proof->A[i]);
            // 计算Di
            EC_POINT_mul(w1->get_curve(), proof->D[i], NULL, proof->U[i], k1, temp_ctx);
            // 计算U'
            EC_POINT_mul(w1->get_curve(), temp_U_, NULL, proof->U[i], a[i], temp_ctx);
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            BIGNUM *Si = BN_hash(
                std::to_string(i),
                w1->to_string(temp_ctx),
                pi.to_string(temp_ctx));
            BN_mod_mul(temp, Si, k1, w1->get_order(), temp_ctx);
            // 计算x_hat
            BN_mod_mul(temp_x_hat, temp, u[i], w1->get_order(), temp_ctx);
            // 计算y_hat
            BN_mod_mul(temp_y_hat, temp, r[i], w1->get_order(), temp_ctx);
            // 利用 Ui 从 U_Evidence 中找到对应的证据Vi
            std::string temp_str_ui = EC_POINT_to_string(w1->get_curve(), proof->U[i], temp_ctx);
            std::string evidence = U_Evidence->at(temp_str_ui);
            Messages::Msg_user_evidence msg_user_evidence;
            msg_user_evidence.ParseFromString(evidence);
            Messages::Msg_ElGamal_ciphertext msg_vi = msg_user_evidence.v();
            V[i] = new ElGamal_ciphertext(w1->get_curve(), msg_vi, temp_ctx);
            std::string temp_str_ai = EC_POINT_to_string(w1->get_curve(), proof->A[i], temp_ctx);
#pragma omp critical
            {
                // 保存 Ai 与 Vi 的关系
                A_V->insert(std::make_pair(temp_str_ai, msg_vi));
                // 累加 U'，x_hat和y_hat
                EC_POINT_add(w1->get_curve(), proof->U_, proof->U_, temp_U_, temp_ctx);
                BN_mod_add(proof->x_hat, proof->x_hat, temp_x_hat, w1->get_order(), temp_ctx);
                BN_mod_add(proof->y_hat, proof->y_hat, temp_y_hat, w1->get_order(), temp_ctx);
            }
            // 释放临时变量
            EC_POINT_free(temp_Ui1);
            EC_POINT_free(temp_Ui2);
            EC_POINT_free(temp_U_);
            BN_free(Si);
            BN_free(temp);
            BN_free(temp_x_hat);
            BN_free(temp_y_hat);
            BN_CTX_free(temp_ctx);
        }

        // 计算 W = k1*G1
        proof->W = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W, NULL, w1->get_G1(), k1, ctx);

        // 计算 W' = k'*G1
        proof->W_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->W_, NULL, w1->get_G1(), k_, ctx);

        // 计算 C1 = k1*U'
        proof->C1 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1, NULL, proof->U_, k1, ctx);

        // 计算 C1' = k'*U'
        proof->C1_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->C1_, NULL, proof->U_, k_, ctx);

        // 计算 A' = x'*G2
        proof->A_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->A_, NULL, w1->get_G2(), x_, ctx);

        // 计算 D' = x'*G0 + y'*H0
        proof->D_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), proof->D_, NULL, w1->get_G0(), x_, ctx);
        EC_POINT *temp = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_H0(), y_, ctx);
        EC_POINT_add(w1->get_curve(), proof->D_, proof->D_, temp, ctx);
        EC_POINT_free(temp);

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        BIGNUM *S0 = BN_hash(
            w1->to_string(ctx),
            p0.to_string(ctx));

        // 计算 k_hat = S0*k1+k'
        proof->k_hat = BN_new();
        BN_mod_mul(proof->k_hat, S0, k1, w1->get_order(), ctx);
        BN_mod_add(proof->k_hat, proof->k_hat, k_, w1->get_order(), ctx);

        BN_CTX_end(ctx);
        // 释放内存
        // BN_free(k1);
        BN_free(k_);
        BN_free(x_);
        BN_free(y_);
        BN_free(S0);
        for (int i = 0; i < user_count_advertiser; i++)
        {
            BN_free(a[i]);
        }
        delete[] a;
    }

    int round_A2(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_a2 = new Message_A2();
        message_a2->user_count_advertiser = user_count_advertiser;
        message_a2->user_count_platform = user_count_platform;
        // 验证上一轮的计算
        {
            // 验证 Z_hat*G2 = P' + t1*P1 + t2*P2 + ... + tn*Pn
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            // 计算 Z_hat*G2
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G2(), message_p1->Z_hat, ctx);
            // 赋值right=P'
            EC_POINT_copy(right, message_p1->P_);
            // 计算 t1*P1 + t2*P2 + ... + tn*Pn
// 并行化
#pragma omp parallel for
            for (int j = 0; j < user_count_platform; ++j)
            {
                BN_CTX *temp_ctx = BN_CTX_new();
                // 计算哈希值 t_j=H(j||W1||P')
                BIGNUM *t_j = BN_hash(
                    std::to_string(j),
                    w1->to_string(temp_ctx),
                    EC_POINT_to_string(w1->get_curve(), message_p1->P_, temp_ctx));
                // 计算 tj*Pj
                EC_POINT *temp = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), temp, NULL, message_p1->P[j], t_j, temp_ctx);
// 线程安全
#pragma omp critical
                {
                    // 累加
                    EC_POINT_add(w1->get_curve(), right, right, temp, temp_ctx);
                }
                // 释放内存
                EC_POINT_free(temp);
                BN_free(t_j);
                BN_CTX_free(temp_ctx);
            }
            // 比较
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A2" << std::endl;
                return 1;
            }
            EC_POINT_free(left);
            EC_POINT_free(right);
        }
        // 选择 m 个随机数 {⍴1,⍴2,...,⍴m}
        BIGNUM **rho = new BIGNUM *[user_count_platform];
        // 选择 m 个随机数 {s1,s2,...,sm}
        BIGNUM **s = new BIGNUM *[user_count_platform];
        // 选择 m 个随机数 {t1,t2,...,tm}
        BIGNUM **t = new BIGNUM *[user_count_platform];
        // 选择一个包含从1到m所有整数的数组π，并将其顺序shuffle
        int *pi = new int[user_count_platform];
        // 保存密文C
        message_a2->C = new ElGamal_ciphertext *[user_count_platform];
        // 保存向量A
        //message_a2->A = new EC_POINT *[user_count_advertiser];
        // 保存向量C1_
        message_a2->C1_ = new EC_POINT *[user_count_advertiser];
        // 保存向量C2_
        message_a2->C2_ = new EC_POINT *[user_count_advertiser];
        // 保存向量x_hat
        message_a2->x_hat = new BIGNUM *[user_count_advertiser];
        // 保存向量y_hat
        message_a2->y_hat = new BIGNUM *[user_count_advertiser];

// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            BIGNUM *r_ = BN_rand(256); // 随机数r'j
            BIGNUM *x_ = BN_rand(256); // 随机数x'j
            BIGNUM *y_ = BN_rand(256); // 随机数y'j
            rho[j] = BN_rand(256);
            s[j] = BN_rand(256);
            t[j] = BN_rand(256);
            pi[j] = j + 1;
            // 计算ElGamal密文 Cj = (k1*Pj + r'j*pkA , r'j*Ha)
            // 设置临时C1和C2
            message_a2->C[j] = new ElGamal_ciphertext(w1->get_curve());
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            // 计算 k1*Pj
            EC_POINT_mul(w1->get_curve(), message_a2->C[j]->C1, NULL, message_p1->P[j], k1, temp_ctx);
            // 计算 r'j*pkA
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_pkA(), r_, temp_ctx);
            // 计算 C1 = k1*Pj + r'j*pkA
            EC_POINT_add(w1->get_curve(), message_a2->C[j]->C1, message_a2->C[j]->C1, temp, temp_ctx);
            // 计算 C2 = r'j*Ha
            EC_POINT_mul(w1->get_curve(), message_a2->C[j]->C2, NULL, w1->get_Ha(), r_, temp_ctx);
            // 计算 C'1j = x'j*Pj + y'j*pkA
            message_a2->C1_[j] = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_ = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->C1_[j], NULL, message_p1->P[j], x_, temp_ctx); // 计算 x'j*Pj
            EC_POINT_mul(w1->get_curve(), temp_, NULL, w1->get_pkA(), y_, temp_ctx);                 // 计算 y'j*pkA
            EC_POINT_add(w1->get_curve(), message_a2->C1_[j], message_a2->C1_[j], temp_, temp_ctx);  // 计算 C'1j = x'j*Pj + y'j*pkA
            // 计算 C'2j = y'j*Ha
            message_a2->C2_[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->C2_[j], NULL, w1->get_Ha(), y_, temp_ctx);
            // 计算哈希值 Sj = H(W1||C'1j||C'2j)
            BIGNUM *Sj = BN_hash(
                w1->to_string(temp_ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->C1_[j], temp_ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->C2_[j], temp_ctx));
            // 计算 x_hatj = Sj*k1 + x'j
            message_a2->x_hat[j] = BN_new();
            BN_mod_mul(message_a2->x_hat[j], Sj, k1, w1->get_order(), temp_ctx);                   // 计算 Sj*k1
            BN_mod_add(message_a2->x_hat[j], message_a2->x_hat[j], x_, w1->get_order(), temp_ctx); // 计算 x_hatj = Sj*k1 + x'j
            // 计算 y_hatj = Sj*r'j + y'j
            message_a2->y_hat[j] = BN_new();
            BN_mod_mul(message_a2->y_hat[j], Sj, r_, w1->get_order(), temp_ctx);                   // 计算 Sj*r'j
            BN_mod_add(message_a2->y_hat[j], message_a2->y_hat[j], y_, w1->get_order(), temp_ctx); // 计算 y_hatj = Sj*r'j + y'j
            // 释放内存
            EC_POINT_free(temp);
            EC_POINT_free(temp_);
            BN_free(r_);
            BN_free(x_);
            BN_free(y_);
            BN_free(Sj);
            BN_CTX_free(temp_ctx);
        }
        // 选择随机数 skA'
        skA_ = BN_rand(256);
        // 使用std::shuffle对数组π进行随机排序
        std::shuffle(pi, pi + user_count_platform, std::default_random_engine(std::random_device()()));
        // 保存密文C'
        message_a2->C_ = new ElGamal_ciphertext *[user_count_platform];
        // 保存密文CA
        message_a2->CA = new EC_POINT *[user_count_platform];
        // 保存向量π
        BIGNUM **pi_ = new BIGNUM *[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 将πj转化为BIGNUM
            pi_[j] = BN_new();
            BN_set_word(pi_[j], pi[j]);
            // 计算 Cj' = (⍴j*pkA, ⍴j*Ha) + C[πj]
            message_a2->C_[j] = new ElGamal_ciphertext(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->C_[j]->C1, NULL, w1->get_pkA(), rho[j], temp_ctx);            // 计算 ⍴j*pkA
            EC_POINT_mul(w1->get_curve(), message_a2->C_[j]->C2, NULL, w1->get_Ha(), rho[j], temp_ctx);             // 计算 ⍴j*Ha
            ElGamal_add(w1->get_curve(), message_a2->C_[j], message_a2->C_[j], message_a2->C[pi[j] - 1], temp_ctx); // 计算 Cj' = (⍴j*pkA, ⍴j*Ha) + C[πj]
            // 计算 CAj = πj*G2 + sj*Ha
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            message_a2->CA[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->CA[j], NULL, w1->get_Ha(), s[j], temp_ctx); // 计算 sj*Ha
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_G2(), pi_[j], temp_ctx);            // 计算 πj*G2
            EC_POINT_add(w1->get_curve(), message_a2->CA[j], message_a2->CA[j], temp, temp_ctx);  // 计算 CAj = πj*G2 + sj*Ha
            // 释放内存
            EC_POINT_free(temp);
            BN_CTX_free(temp_ctx);
        }
        // 计算哈希值 x=H(W1||CA1)
        BIGNUM *x = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a2->CA[0], ctx));
        // 保存密文CB
        message_a2->CB = new EC_POINT *[user_count_platform];
        // 保存向量B
        BIGNUM **B = new BIGNUM *[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 计算 Bj = x^{πj}
            B[j] = BN_new();
            BN_mod_exp(B[j], x, pi_[j], w1->get_order(), temp_ctx);
            // 计算 CBj = Bj*G2 + tj*Ha
            message_a2->CB[j] = EC_POINT_new(w1->get_curve());
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->CB[j], NULL, w1->get_G2(), B[j], temp_ctx);
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_Ha(), t[j], temp_ctx);
            EC_POINT_add(w1->get_curve(), message_a2->CB[j], message_a2->CB[j], temp, temp_ctx);
            // 释放内存
            EC_POINT_free(temp);
            BN_CTX_free(temp_ctx);
        }
        std::string CB1_str = EC_POINT_to_string(w1->get_curve(), message_a2->CB[0], ctx);
        // 计算哈希值 y=H(1||W1||CB1)
        BIGNUM *y = BN_hash(
            "1",
            w1->to_string(ctx),
            CB1_str);
        // 计算哈希值 z=H(2||W1||CB1)
        BIGNUM *z = BN_hash(
            "2",
            w1->to_string(ctx),
            CB1_str);
        // 设置 E=1
        message_a2->E = BN_new();
        BN_one(message_a2->E);
        // 保存向量CD'
        message_a2->CD_ = new EC_POINT *[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 计算 Dj' = Bj + y*πj - z
            BIGNUM *Dj_ = BN_new();
            BN_mod_mul(Dj_, y, pi_[j], w1->get_order(), temp_ctx);
            BN_mod_add(Dj_, Dj_, B[j], w1->get_order(), temp_ctx);
            BN_mod_sub(Dj_, Dj_, z, w1->get_order(), temp_ctx);
            // 计算 CDj' = Dj'*G2 + (y*sj + tj)*Ha
            message_a2->CD_[j] = EC_POINT_new(w1->get_curve());
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_a2->CD_[j], NULL, w1->get_G2(), Dj_, temp_ctx);  // Dj'*G2
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_Ha(), y, temp_ctx);                  // y*Ha
            EC_POINT_mul(w1->get_curve(), temp, NULL, temp, s[j], temp_ctx);                       // y*sj*Ha
            EC_POINT_add(w1->get_curve(), message_a2->CD_[j], message_a2->CD_[j], temp, temp_ctx); // Dj'*G2 + y*sj*Ha
            EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_Ha(), t[j], temp_ctx);               // tj*Ha
            EC_POINT_add(w1->get_curve(), message_a2->CD_[j], message_a2->CD_[j], temp, temp_ctx); // Dj'*G2 + y*sj*Ha + tj*Ha
// 线程安全
#pragma omp critical
            {
                // 累乘 E = E*Dj'
                BN_mod_mul(message_a2->E, message_a2->E, Dj_, w1->get_order(), temp_ctx);
            }
            // 释放内存
            EC_POINT_free(temp);
            BN_free(Dj_);
            BN_CTX_free(temp_ctx);
        }
        // 计算 ⍴' = -(⍴1*B1 + ⍴2*B2 + ... + ⍴m*Bm)
        BIGNUM *rho_ = BN_new();
        BN_zero(rho_);
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            BIGNUM *temp = BN_new();
            BN_mod_mul(temp, rho[j], B[j], w1->get_order(), temp_ctx); // ⍴j*Bj
// 线程安全
#pragma omp critical
            {
                // 累加 ⍴' = ⍴' + ⍴j*Bj
                BN_mod_add(rho_, rho_, temp, w1->get_order(), temp_ctx);
            }
            BN_free(temp);
            BN_CTX_free(temp_ctx);
        }
        BN_mod_sub(rho_, w1->get_order(), rho_, w1->get_order(), ctx);
        // 保存向量 Q
        message_a2->Q = new EC_POINT *[user_count_platform];
        // 计算 F = (⍴'*pkA, ⍴'*Ha) + B1*C1' + B2*C2' + ... + Bm*Cm'
        message_a2->F = new ElGamal_ciphertext(w1->get_curve(), w1->get_pkA(), w1->get_Ha());
        ElGamal_mul(w1->get_curve(), message_a2->F, message_a2->F, rho_, ctx);
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 计算 Bj*Cj'
            ElGamal_ciphertext *temp_F = new ElGamal_ciphertext();
            ElGamal_mul(w1->get_curve(), temp_F, message_a2->C_[j], B[j], temp_ctx);
            // 计算 Qj = Cj1 + (Cj2*skA)^{-1}
            message_a2->Q[j] = EC_POINT_new(w1->get_curve());
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, message_a2->C_[j]->C2, skA, temp_ctx);        // Cj2*skA
            EC_POINT_invert(w1->get_curve(), temp, temp_ctx);                                       // (Cj2*skA)^{-1}
            EC_POINT_add(w1->get_curve(), message_a2->Q[j], message_a2->C_[j]->C1, temp, temp_ctx); // Cj1 + (Cj2*skA)^{-1}
            
// 线程安全
#pragma omp critical
            {
                // 累加 F = F + Bj*Cj'
                ElGamal_add(w1->get_curve(), message_a2->F, message_a2->F, temp_F, temp_ctx);
            }
            // 释放内存
            EC_POINT_free(temp);
            delete temp_F;
            BN_CTX_free(temp_ctx);
        }
        // 计算 GS = skA*G2
        message_a2->GS = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a2->GS, NULL, w1->get_G2(), skA, ctx);
        // 计算 GS' = skA'*G2
        message_a2->GS_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a2->GS_, NULL, w1->get_G2(), skA_, ctx);
        // 计算 pkA' = skA'*Ha
        message_a2->pkA_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a2->pkA_, NULL, w1->get_Ha(), skA_, ctx);
        // 计算哈希值 ts=H(W1||GS'||pkA')
        BIGNUM *ts = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a2->GS_, ctx),
            EC_POINT_to_string(w1->get_curve(), message_a2->pkA_, ctx));
        // 计算 skA_hat = ts*skA + skA'
        message_a2->skA_hat = BN_new();
        BN_mod_mul(message_a2->skA_hat, ts, skA, w1->get_order(), ctx);
        BN_mod_add(message_a2->skA_hat, message_a2->skA_hat, skA_, w1->get_order(), ctx);
        // 释放内存
        BN_free(ts);
        BN_free(rho_);
        BN_free(x);
        BN_free(y);
        BN_free(z);
        // 释放r,⍴,s,t,π,B
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_free(rho[j]);
            BN_free(s[j]);
            BN_free(t[j]);
            BN_free(pi_[j]);
            BN_free(B[j]);
        }
        delete[] rho;
        delete[] s;
        delete[] t;
        delete[] pi_;
        delete[] pi;
        delete[] B;
        BN_CTX_end(ctx);
        return 0;
    }

    int round_A4(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_a4 = new Message_A4();
        // 验证上一轮的计算
        {
            // 计算 ta=H(W1||C3')
            BIGNUM *ta = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(), message_p3->C3_, ctx));
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            // 验证 kq_hat*A' = ta*C3 + C3'
            EC_POINT_mul(w1->get_curve(), left, NULL, message_p3->A_, message_p3->kq_hat, ctx);
            EC_POINT_mul(w1->get_curve(), right, NULL, message_p3->C3, ta, ctx);
            EC_POINT_add(w1->get_curve(), right, right, message_p3->C3_, ctx);
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: kq_hat*A' != ta*C3 + C3'" << std::endl;
                return 1;
            }
            // 释放内存
            BN_free(ta);
            EC_POINT_free(left);
            EC_POINT_free(right);
        }
        // 将向量J的值存入向量X中
        std::string *X = new std::string[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            char *temp_J = EC_POINT_point2hex(w1->get_curve(), message_a2->Q[j], POINT_CONVERSION_COMPRESSED, temp_ctx);
            X[j] = temp_J;
            // 释放内存
            OPENSSL_free(temp_J);
            BN_CTX_free(temp_ctx);
        }
        // 使用unordered_map存储Li与Ai的关系，并将其分配在堆内存中
        std::unordered_map<std::string, std::string> *L_A = new std::unordered_map<std::string, std::string>();
        // 将向量L的值存入向量Y中
        std::string *Y = new std::string[user_count_advertiser];
// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            char *temp_L = EC_POINT_point2hex(w1->get_curve(), message_p3->L[i], POINT_CONVERSION_COMPRESSED, temp_ctx);
            char *temp_A = EC_POINT_point2hex(w1->get_curve(), A[i], POINT_CONVERSION_COMPRESSED, temp_ctx);
            Y[i] = temp_L;
            //std::cout<<"i"<<i<<Y[i]<<std::endl;
// 线程安全
#pragma omp critical
            L_A->insert(std::make_pair(
                temp_L,
                temp_A));
            // 释放内存
            OPENSSL_free(temp_L);
            OPENSSL_free(temp_A);
            BN_CTX_free(temp_ctx);
        }
        // 对向量X进行排序
        std::sort(X, X + user_count_platform);
        // 对向量Y进行排序
        std::sort(Y, Y + user_count_advertiser);
        // 定义交集向量
        std::vector<std::string> *intersection = new std::vector<std::string>();
        // 使用set_intersection计算向量J与向量X的交集，当向量J中的元素与向量X中元素的first相同时，将向量X的元素存入交集向量intersection中
        std::set_intersection(
            X, X + user_count_platform,
            Y, Y + user_count_advertiser,
            std::back_inserter(*intersection));

        // 同态累加交集向量中的 ElGamal_ciphertext 得到 Sum_E
        ElGamal_ciphertext *Sum_E = nullptr;
        if (intersection->size() > 0)
        {   
            // 将Sum_E赋值为交集向量中的第一个元素在A_V中的value
            Sum_E = new ElGamal_ciphertext(w1->get_curve(), A_V->at(L_A->at(intersection->at(0))), ctx);
            // 循环累加交集向量中的 ElGamal_ciphertext
            for (size_t i = 1; i < intersection->size(); ++i)
            {
                //std::cout<<intersection->at(i)<<std::endl;
                ElGamal_ciphertext *temp = new ElGamal_ciphertext(w1->get_curve(), A_V->at(L_A->at(intersection->at(i))), ctx);
                ElGamal_add(w1->get_curve(), Sum_E, Sum_E, temp, ctx);
                delete temp;
            }
        }
        else
        {
            // 生成变量0
            BIGNUM *zero = BN_new();
            BN_zero(zero);
            Sum_E = ElGamal_encrypt(w1, zero, ctx);
            BN_free(zero);
        }
        //std::cout<<Sum_E->to_string(w1->get_curve(),ctx)<<std::endl;
        message_a4->Sum_E = new ElGamal_ciphertext(w1->get_curve(),Sum_E);
        // 解密Sum_E
        EC_POINT *Sum_D = ElGamal_decrypt(w1, skA, Sum_E, ctx);
        // 测试Sum_D是否等于Sum_d
        if (EC_POINT_cmp(w1->get_curve(), Sum_D, Sum_d, ctx) != 0)
        {
            std::cout << "failed: A4" << std::endl;
            std::cout << "Sum_D != Sum_d" << std::endl;
        }
        // 选择随机数 skA''
        BIGNUM *skA__ = BN_rand(256);
        // 计算 GK = skA*Ga
        message_a4->GK = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4->GK, NULL, w1->get_Ga(), skA, ctx);
        // 计算 GK' = skA''*Ga
        message_a4->GK_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4->GK_, NULL, w1->get_Ga(), skA__, ctx);
        // 计算 pkA'' = skA''*Ha
        message_a4->pkA__ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4->pkA__, NULL, w1->get_Ha(), skA__, ctx);
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        BIGNUM *tb = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4->GK_, ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4->pkA__, ctx));
        // 计算 skA_hat = tb*skA + skA'
        message_a4->skA_hat_ = BN_new();
        BN_mod_mul(message_a4->skA_hat_, tb, skA, w1->get_order(), ctx);
        BN_mod_add(message_a4->skA_hat_, message_a4->skA_hat_, skA__, w1->get_order(), ctx);

        // std::cout<<EC_POINT_point2oct(w1->get_curve(), A[0], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx)<<std::endl;
        // std::cout<<message_a4->Sum_E->get_size(w1->get_curve(), ctx)<<std::endl;


        // 释放内存L_A,X,Y,intersection,Sum_E,skA__,tb
        delete L_A;
        delete[] X;
        delete[] Y;
        delete intersection;
        delete Sum_E;
        EC_POINT_free(Sum_D);
        BN_free(skA__);
        BN_free(tb);
        BN_CTX_end(ctx);
        return 0;
    }

    int round_A4_(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_a4_ = new Message_A4_();
        // 验证上一轮的计算
        {
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            bool result_Ai = true;
            bool result_Ha = true;
#pragma omp parallel for           
            for (int i = 0; i < user_count_advertiser; ++i)
            {     
                BN_CTX* temp_ctx = BN_CTX_new();
                EC_POINT *left1 = EC_POINT_new(w1->get_curve());
                EC_POINT *right1 = EC_POINT_new(w1->get_curve());
                //计算hash(w1||ct1i||ct2i)
                BIGNUM *Si_ = BN_hash(
                    w1->to_string(temp_ctx),
                    EC_POINT_to_string(w1->get_curve(),message_p3_->Ct1_[i],temp_ctx),
                    EC_POINT_to_string(w1->get_curve(),message_p3_->Ct2_[i],temp_ctx)
                );
                EC_POINT *tempt = EC_POINT_new(w1->get_curve());
                //加密验证：x_hat_[i]*Ai + y_hat_[i]*pk_p = s_[i]*Ct1[i]+Ct1_[i]
                EC_POINT_mul(w1->get_curve(),left1,NULL,A[i],message_p3_->x_hat_[i],temp_ctx);
                EC_POINT_mul(w1->get_curve(),tempt,NULL,message_p3_->pk_p,message_p3_->y_hat_[i],temp_ctx);
#pragma omp critical
                EC_POINT_add(w1->get_curve(),left1,left1,tempt,temp_ctx);
                EC_POINT_mul(w1->get_curve(),right1,NULL,message_p3_->Ct[i]->C1,Si_,temp_ctx);
#pragma omp critical
                EC_POINT_add(w1->get_curve(),right1,right1,message_p3_->Ct1_[i],temp_ctx);   
#pragma omp critical                                                                       
#pragma omp atomic                
                result_Ai &= (EC_POINT_cmp(w1->get_curve(), left1, right1, ctx)==0);
                EC_POINT_free(right1);
                EC_POINT_free(left1);
                //加密验证：y_hat_[i]*Ha = s_[i]*Ct2[i]+Ct2_[i]
                EC_POINT *left2 = EC_POINT_new(w1->get_curve());
                EC_POINT *right2 = EC_POINT_new(w1->get_curve());                
                EC_POINT_mul(w1->get_curve(),left2,NULL,w1->get_Ha(),message_p3_->y_hat_[i],temp_ctx);
                EC_POINT_mul(w1->get_curve(),right2,NULL,message_p3_->Ct[i]->C2,Si_,temp_ctx);
//#pragma omp critical
                EC_POINT_add(w1->get_curve(),right2,right2,message_p3_->Ct2_[i],temp_ctx);
#pragma omp critical              
#pragma omp atomic                
                result_Ha &= (EC_POINT_cmp(w1->get_curve(), left2, right2, ctx)==0);     
                EC_POINT_free(tempt);
                EC_POINT_free(right2);
                EC_POINT_free(left2);
                BN_free(Si_);
                BN_CTX_free(temp_ctx);
            }
            if (!result_Ai)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: x_hat_[i]*Ai + y_hat_[i]*pk_p != s_[i]*Ct1[i]+Ct1_[i]" << std::endl;
                return 1;
            }
            if (!result_Ha)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "   A4: y_hat_[i]*Ha != s_[i]*Ct2[i]+Ct2_[i]" << std::endl;
                return 1;
            }
            //计算x_=Hash(w1||CA[1])
            BIGNUM *x_ = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(),message_p3_->CA_[0],ctx)
            );
            //计算y_=Hash(w1||CB1),z_=Hash(w1||CB2)
            std::string CB2_str = EC_POINT_to_string(w1->get_curve(), message_p3_->CB_[0], ctx);
            BIGNUM *y_ = BN_hash(
                "1",
                w1->to_string(ctx),
                CB2_str
            );
            BIGNUM *z_ = BN_hash(
                "2",
                w1->to_string(ctx),
                CB2_str
            );
            //初始化E''=1
            BIGNUM *E__ ;
            E__ = BN_new();
            BN_one(E__);
            //初始化Ct_x_ = Ct[1]*x_
            ElGamal_ciphertext *Ct_x_  = new ElGamal_ciphertext(w1->get_curve(), message_p3_->Ct[0]->C1, message_p3_->Ct[0]->C2);
            ElGamal_mul(w1->get_curve(), Ct_x_, Ct_x_, x_, ctx);
            //初始化V_x_ = V[0]*x_
            ElGamal_ciphertext *V_x_  = new ElGamal_ciphertext(w1->get_curve(), V[0]->C1, V[0]->C2);
            ElGamal_mul(w1->get_curve(), V_x_, V_x_, x_, ctx);
            bool result_CD = true;
#pragma omp parallel for
            for (int i = 0; i < user_count_advertiser; ++i)
            {     
                BN_CTX* temp_ctx = BN_CTX_new();
                EC_POINT *right1 = EC_POINT_new(w1->get_curve());
                //计算CDi'=y'*CAi'+CBi'
                EC_POINT *CDi_ = EC_POINT_new(w1->get_curve());
                EC_POINT *CZi_ = EC_POINT_new(w1->get_curve());
#pragma omp critical
                EC_POINT_mul(w1->get_curve(),CDi_,w1->get_order(),message_p3_->CA_[i],y_,temp_ctx);
                EC_POINT_add(w1->get_curve(),CDi_,CDi_,message_p3_->CB_[i],temp_ctx);
                //计算CZi' = z'*G_2               
                EC_POINT_mul(w1->get_curve(),CZi_,NULL,w1->get_G2(),z_,temp_ctx);
                EC_POINT_sub(w1->get_curve(),right1,CDi_,CZi_,temp_ctx);
#pragma omp critical                           
#pragma omp atomic
                //验证CDi''=CDi'-CZi'
                result_CD &= (EC_POINT_cmp(w1->get_curve(), message_p3_->CD__[i], right1, ctx) == 0);
                //计算E''=E''*(y'*i+x'^(i)-z')
                BIGNUM *x_i_sub_z,*big_i,*y_i_,*x_big_i;
                x_i_sub_z = BN_new();
                big_i = BN_new();
                y_i_ =BN_new();
                x_big_i = BN_new();
                BN_set_word(big_i,i+1);
                BN_mod_exp(x_big_i,x_,big_i,w1->get_order(),temp_ctx);
                BN_mod_sub(x_i_sub_z,x_big_i,z_,w1->get_order(),temp_ctx);
                BN_mod_mul(y_i_,y_,big_i,w1->get_order(),temp_ctx);
                BN_mod_add(y_i_,y_i_,x_i_sub_z,w1->get_order(),temp_ctx); 
#pragma omp critical
                BN_mod_mul(E__,E__,y_i_,w1->get_order(),temp_ctx);                
                BN_mod_exp(x_big_i,x_,big_i,w1->get_order(),temp_ctx);
                if (i > 0)
                {
                    // 计算 x^i
                    BIGNUM *temp_x_i = BN_new();
                    BN_mod_exp(temp_x_i, x_, big_i, w1->get_order(), temp_ctx);
                    // 计算 Ct[i]*x^(i) 
                    ElGamal_ciphertext *temp_c1 = new ElGamal_ciphertext();
                    ElGamal_mul(w1->get_curve(), temp_c1, message_p3_->Ct[i], temp_x_i, temp_ctx);
#pragma omp critical
                    //Ct_x_ = Ct_x_+Ct[i]*x^(i) 
                    ElGamal_add(w1->get_curve(), Ct_x_, Ct_x_, temp_c1, temp_ctx);
                    // 计算 V[i]*x^(i)  
                    ElGamal_ciphertext *temp_c2 = new ElGamal_ciphertext();
                    ElGamal_mul(w1->get_curve(), temp_c2, V[i], temp_x_i, temp_ctx);
#pragma omp critical
                    //计算V_x_ = V_x_+V[i]*x^(i)
                    ElGamal_add(w1->get_curve(), V_x_, V_x_, temp_c2, temp_ctx);
                    BN_free(temp_x_i);
                    delete temp_c1;
                    delete temp_c2;
                }
                BN_free(big_i);
                BN_free(x_big_i);
                BN_free(x_i_sub_z);
                BN_free(y_i_);
                EC_POINT_free(right1);
                EC_POINT_free(CDi_);
                EC_POINT_free(CZi_);
                BN_CTX_free(temp_ctx);
            }
            if (!result_CD){
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: CDi''=CDi'-CZi'" << std::endl;
                //return 1;
            }
            //验证E''=E'
            if (BN_cmp(E__,message_p3_->E_) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: E''!=E'" << std::endl;
                //return 1;
            }
            //验证Ct^(x')=F'
            if (ElGamal_ciphertext_cmp(w1->get_curve(),message_p3_->F_,Ct_x_,ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: Ct^(x')!=F'" << std::endl;
                //return 1;
            }
            //验证V^(x')=F''
            if (ElGamal_ciphertext_cmp(w1->get_curve(),V_x_,message_p3_->F__,ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: V^(x') != F''" << std::endl;
                //return 1;
            }

            //tp_h = Hash(w1||GSP||pk_p')
            BIGNUM *tp_h = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(),message_p3_->GSP_,ctx),
                EC_POINT_to_string(w1->get_curve(),message_p3_->pk_p_,ctx)
            );
            //验证sk_p_hat*G2 = tp*GSP+GSP'
            EC_POINT_mul(w1->get_curve(), left, w1->get_order(), w1->get_G2(), message_p3_->sk_p_hat, ctx);
            EC_POINT_mul(w1->get_curve(), right, w1->get_order(), message_p3_->GSP, tp_h, ctx);
            EC_POINT_add(w1->get_curve(), right, right, message_p3_->GSP_, ctx);
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: sk_p_hat*G2 != tp*GSP+GSP'" << std::endl;
                //return 1;
            }

            //验证sk_p_hat*Ha = tp*pk_p+pk_p'
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message_p3_->sk_p_hat, ctx);
            EC_POINT_mul(w1->get_curve(), right, NULL, message_p3_->pk_p, tp_h, ctx);
            EC_POINT_add(w1->get_curve(), right, right, message_p3_->pk_p_, ctx);
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: A4" << std::endl;
                std::cout << "A4: sk_p_hat*Ha = tp*pk_p+pk_p'" << std::endl;
                //return 1;
            }
            // 释放内存
            BN_free(tp_h);
            EC_POINT_free(left);
            EC_POINT_free(right);
        }

        // 将向量J的值存入向量X中
        std::string *X = new std::string[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            char *temp_J = EC_POINT_point2hex(w1->get_curve(), message_a2->Q[j], POINT_CONVERSION_COMPRESSED, temp_ctx);
            X[j] = temp_J;
            // 释放内存
            OPENSSL_free(temp_J);
            BN_CTX_free(temp_ctx);
        }
        // 使用unordered_map存储Li与Vi的关系，并将其分配在堆内存中
        std::unordered_map<std::string, Messages::Msg_ElGamal_ciphertext> *L_V = nullptr;
        L_V = new std::unordered_map<std::string, Messages::Msg_ElGamal_ciphertext>();

        // 将向量L的值存入向量Y中
        std::string *Y = new std::string[user_count_advertiser];
// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            char *temp_L = EC_POINT_point2hex(w1->get_curve(), message_p3_->L[i], POINT_CONVERSION_COMPRESSED, temp_ctx);
            Messages::Msg_ElGamal_ciphertext temp_V ;
            temp_V = *message_p3_->V_[i]->serialize(w1->get_curve(),temp_ctx);
            Y[i] = temp_L;
#pragma omp critical
            L_V->insert(std::make_pair(temp_L,temp_V));
            // 释放内存
            OPENSSL_free(temp_L);
            BN_CTX_free(temp_ctx);
        }
        // 对向量X进行排序
        std::sort(X, X + user_count_platform);
        // 对向量Y进行排序
        std::sort(Y, Y + user_count_advertiser);
        // 定义交集向量
        std::vector<std::string> *intersection = new std::vector<std::string>();
        // 使用set_intersection计算向量J与向量X的交集，当向量J中的元素与向量X中元素的first相同时，将向量X的元素存入交集向量intersection中
        std::set_intersection(
            X, X + user_count_platform,
            Y, Y + user_count_advertiser,
            std::back_inserter(*intersection));

        // 同态累加交集向量中的 ElGamal_ciphertext 得到 Sum_E
        ElGamal_ciphertext *Sum_E = nullptr;
        if (intersection->size() > 0)
        {   
            // 将Sum_E赋值为交集向量中的第一个元素在L_V中的value
            Sum_E = new ElGamal_ciphertext(w1->get_curve(), L_V->at(intersection->at(0)), ctx); 
            // 循环累加交集向量中的 ElGamal_ciphertext
            for (size_t i = 1; i < intersection->size(); ++i)
            {   
                //std::cout<<intersection->at(i)<<std::endl;
                ElGamal_ciphertext *temp = new ElGamal_ciphertext(w1->get_curve(), L_V->at(intersection->at(i)), ctx);
                ElGamal_add(w1->get_curve(), Sum_E, Sum_E, temp, ctx);
                delete temp;
            }
        }
        else
        {
            // 生成变量0
            BIGNUM *zero = BN_new();
            BN_zero(zero);
            Sum_E = ElGamal_encrypt(w1, zero, ctx);
            BN_free(zero);
        }
        //std::cout<<Sum_E->to_string(w1->get_curve(),ctx)<<std::endl;
        message_a4_->Sum_E = new ElGamal_ciphertext(w1->get_curve(),Sum_E);
        // 解密Sum_E
        EC_POINT *Sum_D = ElGamal_decrypt(w1, skA, Sum_E, ctx);
        // 测试Sum_D是否等于Sum_d
        if (EC_POINT_cmp(w1->get_curve(), Sum_D, Sum_d, ctx) != 0)
        {
            std::cout << "failed: A4" << std::endl;
            std::cout << "Sum_D != Sum_d" << std::endl;
        }
        // 选择随机数 skA''
        BIGNUM *skA__ = BN_rand(256);
        // 计算 GK = skA*Ga
        message_a4_->GK = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4_->GK, NULL, w1->get_Ga(), skA, ctx);
        // 计算 GK' = skA''*Ga
        message_a4_->GK_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4_->GK_, NULL, w1->get_Ga(), skA__, ctx);
        // 计算 pkA'' = skA''*Ha
        message_a4_->pkA__ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_a4_->pkA__, NULL, w1->get_Ha(), skA__, ctx);
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        BIGNUM *tb = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4_->GK_, ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4_->pkA__, ctx));
        // 计算 skA_hat = tb*skA + skA'
        message_a4_->skA_hat_ = BN_new();
        BN_mod_mul(message_a4_->skA_hat_, tb, skA, w1->get_order(), ctx);
        BN_mod_add(message_a4_->skA_hat_, message_a4_->skA_hat_, skA__, w1->get_order(), ctx);
        // 释放内存L_A,X,Y,intersection,Sum_E,skA__,tb
        delete L_V;
        delete[] X;
        delete[] Y;
        delete intersection;
        delete Sum_E;
        EC_POINT_free(Sum_D);
        BN_free(skA__);
        BN_free(tb);
        BN_CTX_end(ctx);
        return 0;
    }

    // set U_Evidence
    void set_U_Evidence(std::unordered_map<std::string, std::string> *U_Evidence)
    {
        this->U_Evidence = U_Evidence;
    }
    // set u和r
    void set_user_datas(std::string *user_datas_advertiser)
    {
        this->u = new BIGNUM *[user_count_advertiser];
        this->r = new BIGNUM *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            Messages::Msg_user_data user_data;
            user_data.ParseFromString(user_datas_advertiser[i]);
            this->u[i] = BN_deserialize(user_data.u());
            this->r[i] = BN_deserialize(user_data.r());
        }
    }
    // set user_count
    void set_user_count(int user_count) { this->user_count_advertiser = user_count; }

    // get skA
    BIGNUM *get_skA() { return skA; }
    // set Sum_d
    void debug_set_Sum_d(EC_POINT *Sum_d) { this->Sum_d = Sum_d; }

    void set_message_p1(std::string message, BN_CTX *ctx)
    {
        message_p1 = new Message_P1(w1->get_curve(), message, user_count_platform, ctx);
    }

    void set_message_p3(std::string message, BN_CTX *ctx)
    {
        message_p3 = new Message_P3(w1->get_curve(), message, user_count_advertiser, user_count_platform, ctx);
    }

    void set_message_p3_(std::string message, BN_CTX *ctx)
    {
        message_p3_ = new Message_P3_(w1->get_curve(), message, user_count_advertiser, user_count_platform, ctx);
        msg_p3_ = message;
    }
    std::string get_proof(BN_CTX *ctx) { return proof->serialize(w1->get_curve(), ctx); }
    std::string get_message_a2(BN_CTX *ctx)
    {
        return message_a2->serialize(w1->get_curve(), ctx);
    }
    std::string get_message_a4(BN_CTX *ctx) { return message_a4->serialize(w1->get_curve(), ctx); }
    std::string get_message_a4_(BN_CTX *ctx) { return message_a4_->serialize(w1->get_curve(), ctx); }
};