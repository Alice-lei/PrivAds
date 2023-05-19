#pragma once
#include "base.h"
#include "ec.h"
#include "hash.h"
#include "Messages.h"

class Platform
{
    W1 *w1;
    int user_count_advertiser;
    int user_count_platform;
    // 广告主拥有的用户身份标识
    BIGNUM **user_id_platform = nullptr,**u = nullptr, **r = nullptr;
    // 证明Proof
    Proof *proof = nullptr;
    Message_P1 *message_p1 = nullptr;
    Message_A2 *message_a2 = nullptr;
    Message_P3 *message_p3 = nullptr;
    Message_P3_ *message_p3_ = nullptr;
    Message_A4 *message_a4 = nullptr;
    Message_A4_ *message_a4_ = nullptr;
    EC_POINT **A = nullptr;

    std::unordered_map<std::string, std::string> *U_Evidence = nullptr;
    // 共享变量
    BIGNUM *k2 = BN_rand(256);
    ElGamal_ciphertext **V;
    EC_POINT **P = nullptr;

public:
    // 构造函数
    Platform(W1 *w1, int user_count_advertiser, int user_count_platform, BIGNUM **user_id_platform) : w1(w1), user_count_advertiser(user_count_advertiser), user_count_platform(user_count_platform), user_id_platform(user_id_platform) {}

    // 析构函数
    ~Platform()
    {
        delete proof;
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
        if (message_p1 != nullptr)
            delete message_p1;
        if (message_a2 != nullptr)
            delete message_a2;
        if (message_p3 != nullptr)
            delete message_p3;
        if (message_a4 != nullptr)
            delete message_a4;
        BN_free(k2);
        for (int j = 0; j < user_count_platform; j++)
        {
            EC_POINT_free(P[j]);
        }
        delete[] P;
        if (A != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                EC_POINT_free(A[i]);
            }
            delete[] A;
        }
    }

    // 验证证明
    bool proof_verify(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        EC_POINT *left1 = EC_POINT_new(w1->get_curve());
        EC_POINT *right1 = EC_POINT_new(w1->get_curve());
        EC_POINT *left2 = EC_POINT_new(w1->get_curve());
        EC_POINT *right2 = EC_POINT_new(w1->get_curve());
        EC_POINT *left3 = EC_POINT_new(w1->get_curve());
        EC_POINT *right3 = EC_POINT_new(w1->get_curve());
        EC_POINT *left4 = EC_POINT_new(w1->get_curve());
        EC_POINT *right4 = EC_POINT_new(w1->get_curve());

        // 设置公开参数组P0
        P0 p0(w1->get_curve(), proof->W_, proof->C1_);

        // 计算哈希值 S0 = hash(W1||P0)
        BIGNUM *S0 = BN_hash(
            w1->to_string(ctx),
            p0.to_string(ctx));

        // 验证等式是否成立: k_hat*G1 = S0*W + W'
        EC_POINT_mul(w1->get_curve(), left1, NULL, w1->get_G1(), proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right1, NULL, proof->W, S0, ctx);
        EC_POINT_add(w1->get_curve(), right1, right1, proof->W_, ctx);

        // 验证等式是否成立: k_hat*U' = S0*C1 + C1'
        EC_POINT_mul(w1->get_curve(), left2, NULL, proof->U_, proof->k_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right2, NULL, proof->C1, S0, ctx);
        EC_POINT_add(w1->get_curve(), right2, right2, proof->C1_, ctx);

        // 验证等式是否成立: x_hat*G2 = A' + S1*A1 + S2*A2 + ... + Sn*An
        EC_POINT_mul(w1->get_curve(), left3, NULL, w1->get_G2(), proof->x_hat, ctx);
        // 将A'赋值给right
        EC_POINT_copy(right3, proof->A_);

        // 验证等式是否成立: x_hat*G0 + y_hat*H0 = D' + S1*D1 + S2*D2 + ... + Sn*Dn
        EC_POINT_mul(w1->get_curve(), left4, NULL, w1->get_G0(), proof->x_hat, ctx);
        EC_POINT_mul(w1->get_curve(), right4, NULL, w1->get_H0(), proof->y_hat, ctx);
        EC_POINT_add(w1->get_curve(), left4, left4, right4, ctx);
        // 将D'赋值给right

        EC_POINT_copy(right4, proof->D_);
        proof->U = new EC_POINT *[user_count_advertiser];

        // 为Ui, Ai, Di分配空间
        for (int i = 0; i < user_count_advertiser; i++)
        {
            proof->U[i] = EC_POINT_new(w1->get_curve());
        }
        V = new ElGamal_ciphertext *[user_count_advertiser];
        A = new EC_POINT *[user_count_advertiser];
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

            A[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_copy(A[i], proof->A[i]);
            
            // 利用 Ui 从 U_Evidence 中找到对应的证据Vi
            std::string temp_str_ui = EC_POINT_to_string(w1->get_curve(), proof->U[i], temp_ctx);
            std::string evidence = U_Evidence->at(temp_str_ui);
            Messages::Msg_user_evidence msg_user_evidence;
            msg_user_evidence.ParseFromString(evidence);
            Messages::Msg_ElGamal_ciphertext msg_vi = msg_user_evidence.v();
            V[i] = new ElGamal_ciphertext(w1->get_curve(), msg_vi, temp_ctx);
            std::string temp_str_ai = EC_POINT_to_string(w1->get_curve(), proof->A[i], temp_ctx);

            // 释放临时变量
            EC_POINT_free(temp_Ui1);
            EC_POINT_free(temp_Ui2);
            EC_POINT_free(temp_U_);

            BN_free(temp);
            BN_free(temp_x_hat);
            BN_free(temp_y_hat);
            BN_CTX_free(temp_ctx);
        }


// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; i++)
        {
            // 临时变量
            BN_CTX *temp_ctx = BN_CTX_new();
            EC_POINT *temp_right3 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp_right4 = EC_POINT_new(w1->get_curve());
            // 设置公开参数组Pi
            Pi pi(w1->get_curve(), proof->A[i], proof->D[i]);
            // 计算哈希值 Si = hash(i||W1||Pi)
            BIGNUM *Si = BN_hash(
                std::to_string(i),
                w1->to_string(temp_ctx),
                pi.to_string(temp_ctx));
            // 计算right3
            EC_POINT_mul(w1->get_curve(), temp_right3, NULL, proof->A[i], Si, temp_ctx);
            // 计算right4
            EC_POINT_mul(w1->get_curve(), temp_right4, NULL, proof->D[i], Si, temp_ctx);
            // 多线程加锁
#pragma omp critical
            {
                // 累加right3和right4
                EC_POINT_add(w1->get_curve(), right3, right3, temp_right3, temp_ctx);
                EC_POINT_add(w1->get_curve(), right4, right4, temp_right4, temp_ctx);
            }
            // 释放内存
            BN_CTX_free(temp_ctx);
            EC_POINT_free(temp_right3);
            EC_POINT_free(temp_right4);
            BN_free(Si);
        }

        // 比较，若有一个不相等则返回错误码
        if (EC_POINT_cmp(w1->get_curve(), left1, right1, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left2, right2, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left3, right3, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), left4, right4, ctx) != 0)
        {
            // 打印出错的比较编号
            if (EC_POINT_cmp(w1->get_curve(), left1, right1, ctx) != 0)
            {
                std::cout << "Error 1" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left2, right2, ctx) != 0)
            {
                std::cout << "Error 2" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left3, right3, ctx) != 0)
            {
                std::cout << "Error 3" << std::endl;
            }
            if (EC_POINT_cmp(w1->get_curve(), left4, right4, ctx) != 0)
            {
                std::cout << "Error 4" << std::endl;
            }
            // 释放内存
            BN_CTX_end(ctx);
            BN_free(S0);
            EC_POINT_free(left1);
            EC_POINT_free(right1);
            EC_POINT_free(left2);
            EC_POINT_free(right2);
            EC_POINT_free(left3);
            EC_POINT_free(right3);
            EC_POINT_free(left4);
            EC_POINT_free(right4);
            return false;
        }
        // 释放内存
        BN_CTX_end(ctx);
        BN_free(S0);
        EC_POINT_free(left1);
        EC_POINT_free(right1);
        EC_POINT_free(left2);
        EC_POINT_free(right2);
        EC_POINT_free(left3);
        EC_POINT_free(right3);
        EC_POINT_free(left4);
        EC_POINT_free(right4);
        return true;
    }

    void round_P1(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_p1 = new Message_P1();
        message_p1->user_count_platform = user_count_platform;
        // 选择随机数Z'
        BIGNUM *Z_ = BN_rand(256);
        // 计算 P'=Z'*G2
        message_p1->P_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p1->P_, NULL, w1->get_G2(), Z_, ctx);
        // 设置 Z_hat=Z'
        message_p1->Z_hat = BN_dup(Z_);
        // 保存向量P
        P = new EC_POINT *[user_count_platform];
        message_p1->P = new EC_POINT *[user_count_platform];
// 并行化
#pragma omp parallel for
        for (int j = 0; j < user_count_platform; ++j)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            // 计算 Pj=k2*Wj*G2
            P[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), P[j], NULL, w1->get_G2(), k2, temp_ctx);
            EC_POINT_mul(w1->get_curve(), P[j], NULL, P[j], user_id_platform[j], temp_ctx);
            // 保存向量P
            message_p1->P[j] = EC_POINT_new(w1->get_curve());
            EC_POINT_copy(message_p1->P[j], P[j]);
            // 计算哈希值 t_j=H(j||W1||P')
            BIGNUM *t_j = BN_hash(
                std::to_string(j),
                w1->to_string(temp_ctx),
                EC_POINT_to_string(w1->get_curve(), message_p1->P_, temp_ctx));
            // 计算 Z_hat = Z_hat + tj*k2*Wj
            BIGNUM *temp = BN_new();
            BN_mul(temp, t_j, k2, temp_ctx);
            BN_mul(temp, temp, user_id_platform[j], temp_ctx);
// 线程安全
#pragma omp critical
            // 累加 Z_hat
            BN_add(message_p1->Z_hat, message_p1->Z_hat, temp);
            // 释放内存
            BN_free(temp);
            BN_free(t_j);
            BN_CTX_free(temp_ctx);
        }

        // 释放内存
        BN_free(Z_);
        BN_CTX_end(ctx);
    }

    int round_P3(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_p3 = new Message_P3();
        message_p3->user_count_advertiser = user_count_advertiser;
        message_p3->user_count_platform = user_count_platform;
        // 保存验证4.3的结果
        bool result_4_3 = true;
        // 保存验证4.4的结果
        bool result_4_4 = true;
        // 验证上一轮的计算
        {
            // 计算哈希值x,y,z和ts
            BIGNUM *x = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->CA[0], ctx));
            std::string CB1_str = EC_POINT_to_string(w1->get_curve(), message_a2->CB[0], ctx);
            BIGNUM *y = BN_hash(
                "1",
                w1->to_string(ctx),
                CB1_str);
            BIGNUM *z = BN_hash(
                "2",
                w1->to_string(ctx),
                CB1_str);
            BIGNUM *ts = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->GS_, ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->pkA_, ctx));
            // 保存CD的比较结果
            bool result_CD = true;
            // 保存 E_ = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
            BIGNUM *E_ = BN_new();
            BN_one(E_);
            // 验证 F = C1*x^1 + C2*x^2 + ... + Cm*x^m，赋值 F' = C1*x^1
            ElGamal_ciphertext *F_ = new ElGamal_ciphertext(w1->get_curve(), message_a2->C[0]->C1, message_a2->C[0]->C2);
            ElGamal_mul(w1->get_curve(), F_, F_, x, ctx);
// 并行化
#pragma omp parallel for
            for (int j = 0; j < user_count_platform; ++j)
            {
                BN_CTX *temp_ctx = BN_CTX_new();
                // 将j转换为BIGNUM
                BIGNUM *j_bn = BN_new();
                BN_set_word(j_bn, j + 1);
                // 计算 CDj = y*CAj + CBj - z*G2
                EC_POINT *CDj = EC_POINT_new(w1->get_curve());
                EC_POINT *temp = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), temp, NULL, message_a2->CA[j], y, temp_ctx); // y*CAj
                EC_POINT_add(w1->get_curve(), CDj, temp, message_a2->CB[j], temp_ctx);     // y*CAj + CBj
                EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_G2(), z, temp_ctx);
                EC_POINT_invert(w1->get_curve(), temp, temp_ctx); // -z*G2
                EC_POINT_add(w1->get_curve(), CDj, CDj, temp, temp_ctx);
#pragma omp atomic
                // 比较CD_[j]和CD[j]
                result_CD &= (EC_POINT_cmp(w1->get_curve(), message_a2->CD_[j], CDj, temp_ctx) == 0);
                // 验证 E = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
                BIGNUM *temp1 = BN_new();
                BIGNUM *temp2 = BN_new();
                BN_mod_exp(temp1, x, j_bn, w1->get_order(), temp_ctx);      // x^j
                BN_mod_mul(temp2, y, j_bn, w1->get_order(), temp_ctx);      // y*j
                BN_mod_add(temp1, temp1, temp2, w1->get_order(), temp_ctx); // x^j + y*j
                BN_mod_sub(temp2, temp1, z, w1->get_order(), temp_ctx);     // x^j + y*j - z
#pragma omp critical
                // 累乘 E' = E' * (x^j + y*j - z)
                BN_mod_mul(E_, E_, temp2, w1->get_order(), temp_ctx);
                // 验证 F' = C1*x^1 + C2*x^2 + ... + Cm*x^m
                if (j > 0)
                {
                    // 计算 x^j
                    BIGNUM *temp_x_j = BN_new();
                    BN_mod_exp(temp_x_j, x, j_bn, w1->get_order(), temp_ctx);
                    // 计算 Cj*x^j
                    ElGamal_ciphertext *temp_c = new ElGamal_ciphertext();
                    ElGamal_mul(w1->get_curve(), temp_c, message_a2->C[j], temp_x_j, temp_ctx);
#pragma omp critical
                    // 累加 F' = F' + Cj*x^j
                    ElGamal_add(w1->get_curve(), F_, F_, temp_c, temp_ctx);
                    BN_free(temp_x_j);
                    delete temp_c;
                }
                // 计算哈希值 Sj = H(W1||C'1j||C'2j)
                BIGNUM *Sj = BN_hash(
                    w1->to_string(temp_ctx),
                    EC_POINT_to_string(w1->get_curve(), message_a2->C1_[j], temp_ctx),
                    EC_POINT_to_string(w1->get_curve(), message_a2->C2_[j], temp_ctx));
                // 验证 x_hatj*Pj + y_hatj*pkA = Sj*C1j + C'1j
                EC_POINT *left1 = EC_POINT_new(w1->get_curve());
                EC_POINT *temp_left1 = EC_POINT_new(w1->get_curve());
                EC_POINT *right1 = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), left1, NULL, P[j], message_a2->x_hat[j], temp_ctx);               // x_hatj*Pj
                EC_POINT_mul(w1->get_curve(), temp_left1, NULL, w1->get_pkA(), message_a2->y_hat[j], temp_ctx); // y_hatj*pkA
                EC_POINT_add(w1->get_curve(), left1, left1, temp_left1, temp_ctx);                              // x_hatj*Pj + y_hatj*pkA
                EC_POINT_mul(w1->get_curve(), right1, NULL, message_a2->C[j]->C1, Sj, temp_ctx);                // Sj*C1j
                EC_POINT_add(w1->get_curve(), right1, right1, message_a2->C1_[j], temp_ctx);                    // Sj*C1j + C'1j
#pragma omp atomic
                // 比较 left 和 right
                result_4_3 &= (EC_POINT_cmp(w1->get_curve(), left1, right1, temp_ctx) == 0);
                // 验证 y_hatj*Ha = Sj*C2j + C'2j
                EC_POINT *left2 = EC_POINT_new(w1->get_curve());
                EC_POINT *right2 = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), left2, NULL, w1->get_Ha(), message_a2->y_hat[j], temp_ctx); // y_hatj*Ha
                EC_POINT_mul(w1->get_curve(), right2, NULL, message_a2->C[j]->C2, Sj, temp_ctx);          // Sj*C2j
                EC_POINT_add(w1->get_curve(), right2, right2, message_a2->C2_[j], temp_ctx);              // Sj*C2j + C'2j
#pragma omp atomic
                // 比较 left 和 right
                result_4_4 &= (EC_POINT_cmp(w1->get_curve(), left2, right2, temp_ctx) == 0);

                // 释放内存
                BN_free(j_bn);
                BN_free(temp1);
                BN_free(temp2);
                EC_POINT_free(temp);
                EC_POINT_free(CDj);
                EC_POINT_free(left1);
                EC_POINT_free(temp_left1);
                EC_POINT_free(right1);
                EC_POINT_free(left2);
                EC_POINT_free(right2);
                BN_free(Sj);
                BN_CTX_free(temp_ctx);
            }
            // 比较CD_和CD
            if (!result_CD)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "CD_ != CD" << std::endl;
                return 1;
            }
            // 比较 E 和 E_
            if (BN_cmp(message_a2->E, E_) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "E != E_" << std::endl;
                return 1;
            }
            // 比较 F 和 F_
            if (EC_POINT_cmp(w1->get_curve(), message_a2->F->C1, F_->C1, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), message_a2->F->C2, F_->C2, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "F != F_" << std::endl;
                return 1;
            }
            // 验证 x_hatj*Pj + y_hatj*pkA = Sj*C1j + C'1j
            if (!result_4_3)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "x_hatj*Pj + y_hatj*pkA != Sj*C1j + C'1j" << std::endl;
                return 1;
            }
            // 验证 y_hatj*Ha = Sj*C2j + C'2j
            if (!result_4_4)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "y_hatj*Ha != Sj*C2j + C'2j" << std::endl;
                return 1;
            }
            // 验证 skA_hat*G2 = ts*GS + GS'
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G2(), message_a2->skA_hat, ctx); // skA_hat*G2
            EC_POINT_mul(w1->get_curve(), right, NULL, message_a2->GS, ts, ctx);               // ts*GS
            EC_POINT_add(w1->get_curve(), right, right, message_a2->GS_, ctx);                 // ts*GS + GS'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*G2 != ts*GS + GS'" << std::endl;
                return 1;
            }
            // 验证 skA_hat*Ha = ts*pkA + pkA'
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message_a2->skA_hat, ctx); // skA_hat*Ha
            EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), ts, ctx);                // ts*pkA
            EC_POINT_add(w1->get_curve(), right, right, message_a2->pkA_, ctx);                // ts*pkA + pkA'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*Ha != ts*pkA + pkA'" << std::endl;
                return 1;
            }
            // 释放内存
            EC_POINT_free(left);
            EC_POINT_free(right);
            delete F_;
            BN_free(x);
            BN_free(y);
            BN_free(z);
            BN_free(ts);
            BN_free(E_);
        }
        // 选择随机数 k2'，kq'
        //BIGNUM *k2_ = BN_rand(256);
        BIGNUM *kq_ = BN_rand(256);
        // 选择m个随机数 {b1,b2,...,bm}
        //BIGNUM **b = new BIGNUM *[user_count_platform];
        // 选择n个随机数{c1,c2,...,cn}
        BIGNUM **c = new BIGNUM *[user_count_advertiser];
        // 设置 Q'=0
        // 设置 A'=0
        message_p3->A_ = EC_POINT_new(w1->get_curve());
        // 保存向量L
        message_p3->L = new EC_POINT *[user_count_advertiser];
// 并行化
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX *temp_ctx = BN_CTX_new();
            c[i] = BN_rand(256);
            // 计算 Li = k2*Ai
            message_p3->L[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p3->L[i], NULL, A[i], k2, temp_ctx);
            // 计算 A' = A' + ci*Ai
            EC_POINT *temp = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp, NULL, A[i], c[i], temp_ctx);
// 线程安全
#pragma omp critical
            // 累加 A'
            EC_POINT_add(w1->get_curve(), message_p3->A_, message_p3->A_, temp, temp_ctx);
            // 释放内存
            EC_POINT_free(temp);
            BN_CTX_free(temp_ctx);
        }
        // 计算 kq = k2
        BIGNUM *kq = BN_new();
        BN_copy(kq,k2);
        // 计算 C3 = kq*A'
        message_p3->C3 = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C3, NULL, message_p3->A_, kq, ctx);
        // 计算 C3' = kq'*A'
        message_p3->C3_ = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3->C3_, NULL, message_p3->A_, kq_, ctx);
        // 计算哈希值 ta = H(W_1||C3')
        BIGNUM *ta = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_p3->C3_, ctx));
        // 计算 kq_hat = ta*kq + kq'
        message_p3->kq_hat = BN_new();
        BN_mod_mul(message_p3->kq_hat, ta, kq, w1->get_order(), ctx);
        BN_mod_add(message_p3->kq_hat, message_p3->kq_hat, kq_, w1->get_order(), ctx);
        // 释放k2_,kq_,b,c,tq,kq,ta的内存
        //BN_free(k2_);
        BN_free(kq_);
        // for (int j = 0; j < user_count_platform; ++j)
        // {
        //     BN_free(b[j]);
        // }
        // delete[] b;
        for (int j = 0; j < user_count_advertiser; ++j)
        {
            BN_free(c[j]);
        }
        delete[] c;
        BN_free(kq);
        BN_free(ta);
        BN_CTX_end(ctx);
        return 0;
    }

    int round_P3_(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        message_p3_ = new Message_P3_();
        message_p3_->user_count_advertiser = user_count_advertiser;
        message_p3_->user_count_platform = user_count_platform;
        // 保存验证4.3的结果
        bool result_4_3 = true;
        // 保存验证4.4的结果
        bool result_4_4 = true;
        // 验证上一轮的计算
        {
            // 计算哈希值x,y,z和ts
            BIGNUM *x = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->CA[0], ctx));
            std::string CB1_str = EC_POINT_to_string(w1->get_curve(), message_a2->CB[0], ctx);
            BIGNUM *y = BN_hash(
                "1",
                w1->to_string(ctx),
                CB1_str);
            BIGNUM *z = BN_hash(
                "2",
                w1->to_string(ctx),
                CB1_str);
            BIGNUM *ts = BN_hash(
                w1->to_string(ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->GS_, ctx),
                EC_POINT_to_string(w1->get_curve(), message_a2->pkA_, ctx));
            // 保存CD的比较结果
            bool result_CD = true;
            // 保存 E_ = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
            BIGNUM *E_ = BN_new();
            BN_one(E_);
            // 验证 F = C1*x^1 + C2*x^2 + ... + Cm*x^m，赋值 F' = C1*x^1
            ElGamal_ciphertext *F_ = new ElGamal_ciphertext(w1->get_curve(), message_a2->C[0]->C1, message_a2->C[0]->C2);
            ElGamal_mul(w1->get_curve(), F_, F_, x, ctx);
// 并行化
#pragma omp parallel for
            for (int j = 0; j < user_count_platform; ++j)
            {
                BN_CTX *temp_ctx = BN_CTX_new();
                // 将j转换为BIGNUM
                BIGNUM *j_bn = BN_new();
                BN_set_word(j_bn, j + 1);
                // 计算 CDj = y*CAj + CBj - z*G2
                EC_POINT *CDj = EC_POINT_new(w1->get_curve());
                EC_POINT *temp = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), temp, NULL, message_a2->CA[j], y, temp_ctx); // y*CAj
                EC_POINT_add(w1->get_curve(), CDj, temp, message_a2->CB[j], temp_ctx);     // y*CAj + CBj
                EC_POINT_mul(w1->get_curve(), temp, NULL, w1->get_G2(), z, temp_ctx);
                EC_POINT_invert(w1->get_curve(), temp, temp_ctx); // -z*G2
                EC_POINT_add(w1->get_curve(), CDj, CDj, temp, temp_ctx);
#pragma omp atomic
                // 比较CD_[j]和CD[j]
                result_CD &= (EC_POINT_cmp(w1->get_curve(), message_a2->CD_[j], CDj, temp_ctx) == 0);
                // 验证 E = (x^1 + y*1 - z) * (x^2 + y*2 - z) * ... * (x^m + y*m - z)
                BIGNUM *temp1 = BN_new();
                BIGNUM *temp2 = BN_new();
                BN_mod_exp(temp1, x, j_bn, w1->get_order(), temp_ctx);      // x^j
                BN_mod_mul(temp2, y, j_bn, w1->get_order(), temp_ctx);      // y*j
                BN_mod_add(temp1, temp1, temp2, w1->get_order(), temp_ctx); // x^j + y*j
                BN_mod_sub(temp2, temp1, z, w1->get_order(), temp_ctx);     // x^j + y*j - z
#pragma omp critical
                // 累乘 E' = E' * (x^j + y*j - z)
                BN_mod_mul(E_, E_, temp2, w1->get_order(), temp_ctx);
                // 验证 F' = C1*x^1 + C2*x^2 + ... + Cm*x^m
                if (j > 0)
                {
                    // 计算 x^j
                    BIGNUM *temp_x_j = BN_new();
                    BN_mod_exp(temp_x_j, x, j_bn, w1->get_order(), temp_ctx);
                    // 计算 Cj*x^j
                    ElGamal_ciphertext *temp_c = new ElGamal_ciphertext();
                    ElGamal_mul(w1->get_curve(), temp_c, message_a2->C[j], temp_x_j, temp_ctx);
#pragma omp critical
                    // 累加 F' = F' + Cj*x^j
                    ElGamal_add(w1->get_curve(), F_, F_, temp_c, temp_ctx);
                    BN_free(temp_x_j);
                    delete temp_c;
                }
                // 计算哈希值 Sj = H(W1||C'1j||C'2j)
                BIGNUM *Sj = BN_hash(
                    w1->to_string(temp_ctx),
                    EC_POINT_to_string(w1->get_curve(), message_a2->C1_[j], temp_ctx),
                    EC_POINT_to_string(w1->get_curve(), message_a2->C2_[j], temp_ctx));
                // 验证 x_hatj*Pj + y_hatj*pkA = Sj*C1j + C'1j
                EC_POINT *left1 = EC_POINT_new(w1->get_curve());
                EC_POINT *temp_left1 = EC_POINT_new(w1->get_curve());
                EC_POINT *right1 = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), left1, NULL, P[j], message_a2->x_hat[j], temp_ctx);               // x_hatj*Pj
                EC_POINT_mul(w1->get_curve(), temp_left1, NULL, w1->get_pkA(), message_a2->y_hat[j], temp_ctx); // y_hatj*pkA
                EC_POINT_add(w1->get_curve(), left1, left1, temp_left1, temp_ctx);                              // x_hatj*Pj + y_hatj*pkA
                EC_POINT_mul(w1->get_curve(), right1, NULL, message_a2->C[j]->C1, Sj, temp_ctx);                // Sj*C1j
                EC_POINT_add(w1->get_curve(), right1, right1, message_a2->C1_[j], temp_ctx);                    // Sj*C1j + C'1j
#pragma omp atomic
                // 比较 left 和 right
                result_4_3 &= (EC_POINT_cmp(w1->get_curve(), left1, right1, temp_ctx) == 0);
                // 验证 y_hatj*Ha = Sj*C2j + C'2j
                EC_POINT *left2 = EC_POINT_new(w1->get_curve());
                EC_POINT *right2 = EC_POINT_new(w1->get_curve());
                EC_POINT_mul(w1->get_curve(), left2, NULL, w1->get_Ha(), message_a2->y_hat[j], temp_ctx); // y_hatj*Ha
                EC_POINT_mul(w1->get_curve(), right2, NULL, message_a2->C[j]->C2, Sj, temp_ctx);          // Sj*C2j
                EC_POINT_add(w1->get_curve(), right2, right2, message_a2->C2_[j], temp_ctx);              // Sj*C2j + C'2j
#pragma omp atomic
                // 比较 left 和 right
                result_4_4 &= (EC_POINT_cmp(w1->get_curve(), left2, right2, temp_ctx) == 0);

                // 释放内存
                BN_free(j_bn);
                BN_free(temp1);
                BN_free(temp2);
                EC_POINT_free(temp);
                EC_POINT_free(CDj);
                EC_POINT_free(left1);
                EC_POINT_free(temp_left1);
                EC_POINT_free(right1);
                EC_POINT_free(left2);
                EC_POINT_free(right2);
                BN_free(Sj);
                BN_CTX_free(temp_ctx);
            }
            // 比较CD_和CD
            if (!result_CD)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "CD_ != CD" << std::endl;
                return 1;
            }
            // 比较 E 和 E_
            if (BN_cmp(message_a2->E, E_) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "E != E_" << std::endl;
                return 1;
            }
            // 比较 F 和 F_
            if (EC_POINT_cmp(w1->get_curve(), message_a2->F->C1, F_->C1, ctx) != 0 || EC_POINT_cmp(w1->get_curve(), message_a2->F->C2, F_->C2, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "F != F_" << std::endl;
                return 1;
            }
            // 验证 x_hatj*Pj + y_hatj*pkA = Sj*C1j + C'1j
            if (!result_4_3)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "x_hatj*Pj + y_hatj*pkA != Sj*C1j + C'1j" << std::endl;
                return 1;
            }
            // 验证 y_hatj*Ha = Sj*C2j + C'2j
            if (!result_4_4)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "y_hatj*Ha != Sj*C2j + C'2j" << std::endl;
                return 1;
            }
            // 验证 skA_hat*G2 = ts*GS + GS'
            EC_POINT *left = EC_POINT_new(w1->get_curve());
            EC_POINT *right = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_G2(), message_a2->skA_hat, ctx); // skA_hat*G2
            EC_POINT_mul(w1->get_curve(), right, NULL, message_a2->GS, ts, ctx);               // ts*GS
            EC_POINT_add(w1->get_curve(), right, right, message_a2->GS_, ctx);                 // ts*GS + GS'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*G2 != ts*GS + GS'" << std::endl;
                return 1;
            }
            // 验证 skA_hat*Ha = ts*pkA + pkA'
            EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message_a2->skA_hat, ctx); // skA_hat*Ha
            EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), ts, ctx);                // ts*pkA
            EC_POINT_add(w1->get_curve(), right, right, message_a2->pkA_, ctx);                // ts*pkA + pkA'
            // 比较 left 和 right
            if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
            {
                std::cout << "failed: P3" << std::endl;
                std::cout << "skA_hat*Ha != ts*pkA + pkA'" << std::endl;
                return 1;
            }
            // 释放内存
            EC_POINT_free(left);
            EC_POINT_free(right);
            delete F_;
            BN_free(x);
            BN_free(y);
            BN_free(z);
            BN_free(ts);
            BN_free(E_);
        }
        // 选择随机数 k2'，kq'
        BIGNUM *k2_ = BN_rand(256);
        BIGNUM *kq_ = BN_rand(256);
        // 选择m个随机数 {b1,b2,...,bm}

        /*开始与round_P3不同*/

        //生成公钥和私钥
        BIGNUM *sk_p;
        sk_p = BN_rand(256);
        message_p3_->pk_p = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3_->pk_p, NULL, w1->get_Ha(), sk_p, NULL);        
        //初始化L和Ct
        message_p3_->L = new EC_POINT *[user_count_advertiser];
        message_p3_->Ct = new ElGamal_ciphertext *[user_count_advertiser];
        //初始化Ct1_
        message_p3_->Ct1_ = new EC_POINT *[user_count_advertiser];
        //初始化Ct2_
        message_p3_->Ct2_ = new EC_POINT *[user_count_advertiser];
        //初始化xi_hat_以及yi_hat_
        message_p3_->x_hat_ = new BIGNUM *[user_count_advertiser];
        message_p3_->y_hat_ = new BIGNUM *[user_count_advertiser];
        // 计算 kq = k2
        BIGNUM *kq = BN_new();
        BN_copy(kq,k2);

        //选择一个包含从1到n所有整数的数组π，并将其顺序shuffle,最后打乱
        int *_pi = new int[user_count_advertiser];
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX* temp_ctx = BN_CTX_new();
            _pi[i]= i+1;
            // 计算 Li = k2*Ai =kq*Ai 
            message_p3_->L[i] = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p3_->L[i],NULL,A[i],kq,temp_ctx);
            //std::cout<<i<<"   "<<EC_POINT_to_string(w1->get_curve(),message_p3_->L[i],ctx)<<std::endl;
            //计算Ct
            message_p3_->Ct[i] = new ElGamal_ciphertext(w1->get_curve());
            //C1= Li+rri*Pk_P
            BIGNUM *rri;
            rri = BN_new();
            rri = BN_rand(256);
            EC_POINT_mul(w1->get_curve(),message_p3_->Ct[i]->C1,NULL,message_p3_->pk_p,rri,temp_ctx);
            EC_POINT_add(w1->get_curve(),message_p3_->Ct[i]->C1,message_p3_->Ct[i]->C1,message_p3_->L[i],temp_ctx);
            //C2 = rri*Ha
            EC_POINT_mul(w1->get_curve(),message_p3_->Ct[i]->C2,NULL,w1->get_Ha(),rri,temp_ctx);
            //证明上述加密等
            //选择xi__和yi__
            BIGNUM *xi__,*yi__;
            xi__ = BN_new();
            yi__ = BN_new();
            xi__ = BN_rand(256);
            yi__ = BN_rand(256);
            //计算Ct1i_和Ct2i_
            
            EC_POINT *temp_ec = EC_POINT_new(w1->get_curve());
            message_p3_->Ct1_[i] = EC_POINT_new(w1->get_curve());
            message_p3_->Ct2_[i] = EC_POINT_new(w1->get_curve());
            //Ct1i_ = xi__*Ai + yi__*pk_p
            EC_POINT_mul(w1->get_curve(),temp_ec, NULL,A[i],xi__,temp_ctx);
            EC_POINT_mul(w1->get_curve(),message_p3_->Ct1_[i], NULL,message_p3_->pk_p,yi__,temp_ctx);
            EC_POINT_add(w1->get_curve(),message_p3_->Ct1_[i],message_p3_->Ct1_[i],temp_ec,temp_ctx);
            //Ct2i = yi__*Ha
            EC_POINT_mul(w1->get_curve(),message_p3_->Ct2_[i], NULL,w1->get_Ha(),yi__,temp_ctx);
            //计算hash(w1||ct1i||ct2i)
            BIGNUM *Si_ = BN_hash(
                w1->to_string(temp_ctx),
                EC_POINT_to_string(w1->get_curve(),message_p3_->Ct1_[i],temp_ctx),
                EC_POINT_to_string(w1->get_curve(),message_p3_->Ct2_[i],temp_ctx)
            );
            message_p3_->x_hat_[i] = BN_new();
            message_p3_->y_hat_[i] = BN_new();
            //计算xi_hat_[i] = si'*kq + xi''
#pragma omp critical 
        {
            BN_mod_mul(message_p3_->x_hat_[i],Si_,kq,w1->get_order(), ctx);
            BN_mod_add(message_p3_->x_hat_[i],message_p3_->x_hat_[i],xi__,w1->get_order(), ctx);
        }
#pragma omp critical
        {
            //计算yi_hat_[i]= si'*rri + yi''
            BN_mod_mul(message_p3_->y_hat_[i],rri,Si_,w1->get_order(), ctx);
            BN_mod_add(message_p3_->y_hat_[i],message_p3_->y_hat_[i],yi__,w1->get_order(), ctx);
        }
                           
            BN_free(xi__);
            BN_free(yi__);
            BN_free(rri);
            BN_free(Si_);
            BN_CTX_free(temp_ctx);
            EC_POINT_free(temp_ec);

        }
        //选择一个包含从1到n所有整数的数组π，并将其顺序shuffle,最后打乱
         std::shuffle(_pi, _pi + user_count_advertiser, std::default_random_engine(std::random_device()()));
         //初始化Ct_     
        message_p3_->Ct_ = new ElGamal_ciphertext *[user_count_advertiser];

        BIGNUM **_pi_ = new BIGNUM *[user_count_advertiser];

        //初始化CA_,CB_
        message_p3_->CA_ = new EC_POINT *[user_count_advertiser];
        message_p3_->CB_ = new EC_POINT *[user_count_advertiser];

        //定义t_,s_,B_
        BIGNUM **t_,**s_,**B_,**alpha,**delta;
        t_ = new BIGNUM *[user_count_advertiser];
        s_ = new BIGNUM *[user_count_advertiser];
        B_ = new BIGNUM *[user_count_advertiser];
        alpha = new BIGNUM *[user_count_advertiser];
        delta = new BIGNUM *[user_count_advertiser];

#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX* temp_ctx = BN_CTX_new();
            alpha[i] = BN_new();
            alpha[i] = BN_rand(256);
            delta[i] = BN_new();
            delta[i] = BN_rand(256);
            //t_i赋值
            t_[i] = BN_new();
            t_[i] = BN_rand(256);

            //计算Cti_= (alphai*pkp, alphai*Ha) + Ct[πi]
            message_p3_->Ct_[i] = new ElGamal_ciphertext(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), message_p3_->Ct_[i]->C1, NULL, message_p3_->pk_p, alpha[i], temp_ctx);            // 计算 alphai*pkA
            EC_POINT_mul(w1->get_curve(), message_p3_->Ct_[i]->C2, NULL, w1->get_Ha(), alpha[i], temp_ctx);             // 计算 alphai*Ha
#pragma omp critical
            ElGamal_add(w1->get_curve(),message_p3_->Ct_[i],message_p3_->Ct_[i],message_p3_->Ct[_pi[i]-1],temp_ctx);
            //证明   
            s_[i] = BN_new();         
            s_[i] = BN_rand(256);
            // 将πj转化为BIGNUM
            _pi_[i] = BN_new();
            BN_set_word(_pi_[i], _pi[i]);
            //计算CA_[i] = pi_i*G2+S_[i]*Ha
            message_p3_->CA_[i]  = EC_POINT_new(w1->get_curve());
            EC_POINT *temp1 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp2 = EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(),temp1, NULL,w1->get_G2(),_pi_[i],temp_ctx);
            EC_POINT_mul(w1->get_curve(),temp2,NULL, w1->get_Ha(),s_[i],temp_ctx);
            EC_POINT_add(w1->get_curve(), message_p3_->CA_[i],temp1,temp2,temp_ctx);
            EC_POINT_free(temp1);
            EC_POINT_free(temp2);
            BN_CTX_free(temp_ctx);          
        }
    //计算x_=Hash(w1||CA[1])
        BIGNUM *x_ = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(),message_p3_->CA_[0],ctx)
        );
        //初始化alpha_,delta_
        BIGNUM *alpha_,*delta_;
        alpha_ = BN_new();
        delta_ = BN_new();
        BN_zero(alpha_); 
        BN_zero(delta_);     

#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX* temp_ctx = BN_CTX_new();
            EC_POINT *temp1 = EC_POINT_new(w1->get_curve());
            EC_POINT *temp2 = EC_POINT_new(w1->get_curve());         
            //计算CB_[i] = B'[i]*G2+t_[i]*Ha
            //B'[i] = x'^(pi_[i])
            B_[i] = BN_new();
            message_p3_->CB_[i]  = EC_POINT_new(w1->get_curve());          
            BN_mod_exp(B_[i],x_,_pi_[i],w1->get_order(),temp_ctx);            
            EC_POINT_mul(w1->get_curve(),temp1, w1->get_order(),w1->get_G2(),B_[i],temp_ctx);
            EC_POINT_mul(w1->get_curve(),temp2,w1->get_order(), w1->get_Ha(),t_[i],temp_ctx);
            EC_POINT_add(w1->get_curve(), message_p3_->CB_[i],temp1,temp2,temp_ctx);                                  
            BIGNUM *tempn1,*tempn2;
            tempn1= BN_new();
            tempn2= BN_new();
            //计算alpha_ = alpha_ - alpha[i]*B_[i]
            BN_mod_mul(tempn1,B_[i],alpha[i],w1->get_order(),temp_ctx);
#pragma omp critical            
            BN_mod_sub(alpha_,alpha_,tempn1,w1->get_order(),temp_ctx);
            //计算delta_ = delta - delta[i]*B_[i]
            BN_mod_mul(tempn2,B_[i],delta[i],w1->get_order(),temp_ctx);
#pragma omp critical            
            BN_mod_sub(delta_,delta_,tempn2,w1->get_order(),temp_ctx);
        
            BN_free(tempn1);
            BN_free(tempn2);
            EC_POINT_free(temp1);
            EC_POINT_free(temp2);
            BN_CTX_free(temp_ctx);
        }
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
        //初始化CD__
        message_p3_->CD__ = new EC_POINT *[user_count_advertiser];
        //初始化F_,计算F= E(alpha_) = (alpha_*pkp,alpha_*Ha)   
        message_p3_->F_ = new ElGamal_ciphertext(w1->get_curve(), message_p3_->pk_p, w1->get_Ha());
        ElGamal_mul(w1->get_curve(), message_p3_->F_, message_p3_->F_, alpha_, ctx);
        //初始化E_
        message_p3_->E_ = BN_new();
        BN_one(message_p3_->E_);
        //初始化L
        message_p3_->L = new EC_POINT *[user_count_advertiser];
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX* temp_ctx = BN_CTX_new();           
            BIGNUM *Di__,*Di_,*temp1,*di_;
            Di__= BN_new();
            Di_= BN_new();
            temp1= BN_new();
            di_= BN_new();
            //计算Di_=y_*pi_[i]+(X_)^(pi_[i])
            BN_mod_exp(temp1,x_,_pi_[i],w1->get_order(),temp_ctx);
            BN_mod_mul(Di_,y_,_pi_[i],w1->get_order(),temp_ctx);
#pragma omp critical
            BN_mod_add(Di_,Di_,temp1,w1->get_order(),temp_ctx);
            //Di__=Di_-z_
            BN_mod_sub(Di__,Di_,z_,w1->get_order(),temp_ctx);                        
            //计算di_=y_*s_[i]+t_[i]
            BN_mod_mul(di_,y_,s_[i],w1->get_order(),temp_ctx);
#pragma omp critical
            BN_mod_add(di_,di_,t_[i],w1->get_order(),temp_ctx);
            EC_POINT *temp2 = EC_POINT_new(w1->get_curve());
            //计算CDi__= Di_*G2+di_*Ha 
            message_p3_->CD__[i]= EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(),message_p3_->CD__[i],w1->get_order(),w1->get_G2(),Di__,temp_ctx);
            EC_POINT_mul(w1->get_curve(),temp2,w1->get_order(),w1->get_Ha(),di_,temp_ctx);
#pragma omp critical
            EC_POINT_add(w1->get_curve(),message_p3_->CD__[i],message_p3_->CD__[i],temp2,temp_ctx);
#pragma omp critical
            //计算E_ = E_ * D__[i]
            BN_mod_mul(message_p3_->E_,message_p3_->E_,Di__,w1->get_order(),temp_ctx);
            //计算F_= F_ + B_[i]*Ct_[i]
            ElGamal_ciphertext *temp3; 
            temp3 = new ElGamal_ciphertext(w1->get_curve());
            ElGamal_mul(w1->get_curve(),temp3,message_p3_->Ct_[i],B_[i],temp_ctx);
#pragma omp critical
            ElGamal_add(w1->get_curve(),message_p3_->F_,message_p3_->F_,temp3,temp_ctx);
            //解密得到L = {Li i in 1,n}
            message_p3_->L[i]= EC_POINT_new(w1->get_curve());
            EC_POINT_mul(w1->get_curve(), temp2, w1->get_order(),  message_p3_->Ct_[i]->C2, sk_p, temp_ctx);        
            EC_POINT_invert(w1->get_curve(), temp2, temp_ctx);                                       
            EC_POINT_add(w1->get_curve(), message_p3_->L[i], message_p3_->Ct_[i]->C1, temp2, temp_ctx); 

            BN_free(Di_);
            BN_free(Di__);
            BN_free(temp1);
            BN_free(di_);
            EC_POINT_free(temp2);
            BN_CTX_free(temp_ctx);
        }

        //选择一个sk_p_
        BIGNUM *sk_p_;
        sk_p_ = BN_new();
        sk_p_ = BN_rand(256);        
        //message_p3_->pk_p_=Ha*sk_p_
        message_p3_->pk_p_=EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3_->pk_p_,w1->get_order(),w1->get_Ha(),sk_p_,ctx);
        //计算GSP_= sk_p_*G2；GSP= sk_p*G2
        message_p3_->GSP_ = EC_POINT_new(w1->get_curve());
        message_p3_->GSP = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), message_p3_->GSP_,w1->get_order(),w1->get_G2(),sk_p_,ctx);
        EC_POINT_mul(w1->get_curve(), message_p3_->GSP,w1->get_order(),w1->get_G2(),sk_p,ctx);        
        //tp_h = Hash(w1||GSP||pk_p')
        BIGNUM *tp_h = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(),message_p3_->GSP_,ctx),
            EC_POINT_to_string(w1->get_curve(),message_p3_->pk_p_,ctx)
        );
        
        //sk_p_hat = tp_h*sk_p+sk_p_
        message_p3_->sk_p_hat = BN_new();
        BN_mod_mul(message_p3_->sk_p_hat,tp_h,sk_p,w1->get_order(),ctx);
        BN_mod_add(message_p3_->sk_p_hat,message_p3_->sk_p_hat,sk_p_,w1->get_order(),ctx);
        //初始化V
//        V = new ElGamal_ciphertext *[user_count_advertiser];
// #pragma omp parallel for
//         for (int i = 0; i < user_count_advertiser; ++i)
//         {
//             BN_CTX* temp_ctx = BN_CTX_new(); 
//             // 利用 Ui 从 U_Evidence 中找到对应的证据Vi
//             std::string temp_str_ui = EC_POINT_to_string(w1->get_curve(), proof->U[i], temp_ctx);
//             std::string evidence = U_Evidence->at(temp_str_ui);
//             Messages::Msg_user_evidence msg_user_evidence;
//             msg_user_evidence.ParseFromString(evidence);
//             Messages::Msg_ElGamal_ciphertext msg_vi = msg_user_evidence.v();
//             V[i] = new ElGamal_ciphertext(w1->get_curve(), msg_vi, temp_ctx);
//             BN_CTX_free(temp_ctx);
//         }
        //初始化V_
        message_p3_->V_ = new ElGamal_ciphertext *[user_count_advertiser];
        //初始化F__,计算F__= E(delta_) = (delta_*pkA,delta_*Ha)   
        message_p3_->F__ = new ElGamal_ciphertext(w1->get_curve(), w1->get_pkA(), w1->get_Ha()); 
        ElGamal_mul(w1->get_curve(), message_p3_->F__, message_p3_->F__, delta_, ctx);
#pragma omp parallel for
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            BN_CTX* temp_ctx = BN_CTX_new(); 
            //计算V_[i] = E(delta_i)+V[pi_[i]]
            message_p3_->V_[i] = new ElGamal_ciphertext(w1->get_curve(), w1->get_pkA(), w1->get_Ha());
#pragma omp critical 
            ElGamal_mul(w1->get_curve(),message_p3_->V_[i],message_p3_->V_[i],delta[i],temp_ctx);
#pragma omp critical           
            ElGamal_add(w1->get_curve(),message_p3_->V_[i],message_p3_->V_[i],V[_pi[i]-1],temp_ctx);
            //计算F__= F__ + B_[i]*V_[i]                         
            ElGamal_ciphertext *temp1;
            temp1 = new ElGamal_ciphertext(w1->get_curve());
            ElGamal_mul(w1->get_curve(),temp1,message_p3_->V_[i],B_[i],temp_ctx);
#pragma omp critical
            ElGamal_add(w1->get_curve(),message_p3_->F__,message_p3_->F__,temp1,temp_ctx);         
            BN_CTX_free(temp_ctx);
        }

        BN_free(x_);
        BN_free(y_);
        BN_free(z_);
        BN_free(k2_);
        BN_free(kq_);
        BN_free(tp_h);
        
        for (int i = 0; i < user_count_advertiser; ++i)
        {
            //BN_free(c[i]);
            BN_free(s_[i]);
            BN_free(t_[i]);
            BN_free(B_[i]);
            BN_free(delta[i]);
            BN_free(alpha[i]);
        }
        //delete[] c;
        delete[] s_;
        delete[] t_;
        delete[] B_;
        delete[] alpha;
        delete[] delta;
        
        BN_CTX_end(ctx);
        return 0;
    }

    int round_P5(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
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
            char *temp_L = EC_POINT_point2hex(w1->get_curve(), message_p3->L[i], POINT_CONVERSION_COMPRESSED, temp_ctx);
            Messages::Msg_ElGamal_ciphertext temp_V ;
            temp_V = *V[i]->serialize(w1->get_curve(),temp_ctx);
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
        //验证SumE
        if (ElGamal_ciphertext_cmp(w1->get_curve(),Sum_E,message_a4->Sum_E,ctx)!=0){
            std::cout << "failed: P5" << std::endl;
            std::cout << "SumE错误" << std::endl;
            return 1;
        }
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        BIGNUM *tb = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4->GK_, ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4->pkA__, ctx));
        // 验证 skA'_hat*Ga = tb*GK + GK'
        EC_POINT *left = EC_POINT_new(w1->get_curve());
        EC_POINT *right = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ga(), message_a4->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, message_a4->GK, tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message_a4->GK_, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5" << std::endl;
            std::cout << "skA_hat_*Ga != tb*GK + GK'" << std::endl;
        }
        // 验证 skA'_hat*Ha = tb*pkA + pkA''
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message_a4->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message_a4->pkA__, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5" << std::endl;
            std::cout << "skA_hat_*Ha != tb*pkA + pkA''" << std::endl;
            return 1;
        }

        //std::cout<<Sum_E->to_string(w1->get_curve(),ctx)<<std::endl;
        // 释放内存
        EC_POINT_free(left);
        EC_POINT_free(right);
        BN_free(tb);
        BN_CTX_end(ctx);
        return 0;
    }
    int round_P5_(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
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
        //验证SumE
        if (ElGamal_ciphertext_cmp(w1->get_curve(),Sum_E,message_a4_->Sum_E,ctx)!=0){
            std::cout << "failed: P5_" << std::endl;
            std::cout << "SumE错误" << std::endl;
            return 1;
        }
        
        // 计算哈希值 tb = H(W1||GK'||pkA'')
        BIGNUM *tb = BN_hash(
            w1->to_string(ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4_->GK_, ctx),
            EC_POINT_to_string(w1->get_curve(), message_a4_->pkA__, ctx));
        // 验证 skA'_hat*Ga = tb*GK + GK'
        EC_POINT *left = EC_POINT_new(w1->get_curve());
        EC_POINT *right = EC_POINT_new(w1->get_curve());
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ga(), message_a4_->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, message_a4_->GK, tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message_a4_->GK_, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5_" << std::endl;
            std::cout << "skA_hat_*Ga != tb*GK + GK'" << std::endl;
        }
        // 验证 skA'_hat*Ha = tb*pkA + pkA''
        EC_POINT_mul(w1->get_curve(), left, NULL, w1->get_Ha(), message_a4_->skA_hat_, ctx);
        EC_POINT_mul(w1->get_curve(), right, NULL, w1->get_pkA(), tb, ctx);
        EC_POINT_add(w1->get_curve(), right, right, message_a4_->pkA__, ctx);
        if (EC_POINT_cmp(w1->get_curve(), left, right, ctx) != 0)
        {
            std::cout << "failed: P5_" << std::endl;
            std::cout << "skA_hat_*Ha != tb*pkA + pkA''" << std::endl;
            return 1;
        }
        // 释放内存
        EC_POINT_free(left);
        EC_POINT_free(right);
        BN_free(tb);
        BN_CTX_end(ctx);
        return 0;
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
    void set_proof(std::string message, BN_CTX *ctx)
    {
        proof = new Proof(w1->get_curve(), message, user_count_advertiser, ctx);
    }

    // set U_Evidence
    void set_U_Evidence(std::unordered_map<std::string, std::string> *U_Evidence)
    {
        this->U_Evidence = U_Evidence;
    }

    void set_message_a2(std::string message, BN_CTX *ctx)
    {
        message_a2 = new Message_A2(w1->get_curve(), message, user_count_advertiser, user_count_platform, ctx);
    }

    void set_message_a4(std::string message, BN_CTX *ctx)
    {
        message_a4 = new Message_A4(w1->get_curve(), message, ctx);
    }

    void set_message_a4_(std::string message, BN_CTX *ctx)
    {
        message_a4_ = new Message_A4_(w1->get_curve(), message, ctx);
    }
    std::string get_message_p1(BN_CTX *ctx) { return message_p1->serialize(w1->get_curve(), ctx); }
    std::string get_message_p3(BN_CTX *ctx) { return message_p3->serialize(w1->get_curve(), ctx); }
    std::string get_message_p3_(BN_CTX *ctx) { return message_p3_->serialize(w1->get_curve(), ctx); }
};