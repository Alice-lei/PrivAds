#pragma once
#include "base.h"
#include "ElGamal.h"

class User_data
{
public:
    BIGNUM *u, *r, *v;
    // 构造函数
    User_data() {}

    // 深拷贝构造函数
    User_data(User_data *user_data)
    {
        u = BN_dup(user_data->u);
        r = BN_dup(user_data->r);
        if (user_data->v != NULL)
            v = BN_dup(user_data->v);
    }

    // 释放内存
    ~User_data()
    {
        BN_free(u);
        BN_free(r);
        BN_free(v);
    }
};

class Proof
{
public:
    int user_count_advertiser;
    EC_POINT *W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D;
    BIGNUM *k_hat, *x_hat, *y_hat;

    // 构造函数
    Proof() {}

    // 析构函数
    ~Proof()
    {
        EC_POINT_free(W);
        EC_POINT_free(W_);
        EC_POINT_free(C1);
        EC_POINT_free(C1_);
        EC_POINT_free(U_);
        EC_POINT_free(A_);
        EC_POINT_free(D_);
        for (int i = 0; i < user_count_advertiser; i++)
        {
            EC_POINT_free(U[i]);
            EC_POINT_free(A[i]);
            EC_POINT_free(D[i]);
        }
        delete[] U;
        delete[] A;
        delete[] D;
        BN_free(k_hat);
        BN_free(x_hat);
        BN_free(y_hat);
    }

    // 使用COPY深拷贝构造函数
    Proof(EC_GROUP *curve, Proof *proof)
    {
        user_count_advertiser = proof->user_count_advertiser;
        W = EC_POINT_new(curve);
        EC_POINT_copy(W, proof->W);
        W_ = EC_POINT_new(curve);
        EC_POINT_copy(W_, proof->W_);
        C1 = EC_POINT_new(curve);
        EC_POINT_copy(C1, proof->C1);
        C1_ = EC_POINT_new(curve);
        EC_POINT_copy(C1_, proof->C1_);
        U_ = EC_POINT_new(curve);
        EC_POINT_copy(U_, proof->U_);
        A_ = EC_POINT_new(curve);
        EC_POINT_copy(A_, proof->A_);
        D_ = EC_POINT_new(curve);
        EC_POINT_copy(D_, proof->D_);
        U = new EC_POINT *[user_count_advertiser];
        A = new EC_POINT *[user_count_advertiser];
        D = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            U[i] = EC_POINT_new(curve);
            EC_POINT_copy(U[i], proof->U[i]);
            A[i] = EC_POINT_new(curve);
            EC_POINT_copy(A[i], proof->A[i]);
            D[i] = EC_POINT_new(curve);
            EC_POINT_copy(D[i], proof->D[i]);
        }
        k_hat = BN_dup(proof->k_hat);
        x_hat = BN_dup(proof->x_hat);
        y_hat = BN_dup(proof->y_hat);
    }

    // 从string反序列化
    Proof(EC_GROUP *curve, std::string message, int user_count_advertiser, BN_CTX *ctx)
    {
        this->user_count_advertiser = user_count_advertiser;
        Messages::Msg_Proof msg_proof;
        msg_proof.ParseFromString(message);
        BN_CTX_start(ctx);
        W = EC_POINT_deserialize(curve, msg_proof.w(), ctx);
        W_ = EC_POINT_deserialize(curve, msg_proof.w_prime(), ctx);
        C1 = EC_POINT_deserialize(curve, msg_proof.c1(), ctx);
        C1_ = EC_POINT_deserialize(curve, msg_proof.c1_prime(), ctx);
        U_ = EC_POINT_deserialize(curve, msg_proof.u_prime(), ctx);
        A_ = EC_POINT_deserialize(curve, msg_proof.a_prime(), ctx);
        D_ = EC_POINT_deserialize(curve, msg_proof.d_prime(), ctx);
        k_hat = BN_deserialize(msg_proof.k_hat());
        x_hat = BN_deserialize(msg_proof.x_hat());
        y_hat = BN_deserialize(msg_proof.y_hat());
        U = new EC_POINT *[user_count_advertiser];
        A = new EC_POINT *[user_count_advertiser];
        D = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            U[i] = EC_POINT_deserialize(curve, msg_proof.u(i), ctx);
            A[i] = EC_POINT_deserialize(curve, msg_proof.a(i), ctx);
            D[i] = EC_POINT_deserialize(curve, msg_proof.d(i), ctx);
        }
    }

    // 获取Proof的字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        // 计算*W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D的字节数
        size += EC_POINT_point2oct(curve, W, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, W_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C1, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C1_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, U_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, A_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, D_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        for (int i = 0; i < user_count_advertiser; i++)
        {
            size += EC_POINT_point2oct(curve, U[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, A[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, D[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        }
        // 计算k_hat, x_hat, y_hat的字节数
        size += BN_num_bytes(k_hat);
        size += BN_num_bytes(x_hat);
        size += BN_num_bytes(y_hat);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_Proof msg_proof;
        // 序列化*W, *W_, *C1, *C1_, *U_, *A_, *D_, **U, **A, **D
        msg_proof.set_w(EC_POINT_serialize(curve, W, ctx));
        msg_proof.set_w_prime(EC_POINT_serialize(curve, W_, ctx));
        msg_proof.set_c1(EC_POINT_serialize(curve, C1, ctx));
        msg_proof.set_c1_prime(EC_POINT_serialize(curve, C1_, ctx));
        msg_proof.set_u_prime(EC_POINT_serialize(curve, U_, ctx));
        msg_proof.set_a_prime(EC_POINT_serialize(curve, A_, ctx));
        msg_proof.set_d_prime(EC_POINT_serialize(curve, D_, ctx));
        for (int i = 0; i < user_count_advertiser; i++)
        {
            msg_proof.add_u(EC_POINT_serialize(curve, U[i], ctx));
            msg_proof.add_a(EC_POINT_serialize(curve, A[i], ctx));
            msg_proof.add_d(EC_POINT_serialize(curve, D[i], ctx));
        }
        // 序列化k_hat, x_hat, y_hat
        msg_proof.set_k_hat(BN_serialize(k_hat));
        msg_proof.set_x_hat(BN_serialize(x_hat));
        msg_proof.set_y_hat(BN_serialize(y_hat));
        // 将序列化后的Proof写入字符串
        msg_proof.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};

class Message_P1
{
public:
    int user_count_platform;
    EC_POINT *P_ = nullptr;
    EC_POINT **P = nullptr;
    BIGNUM *Z_hat = nullptr;

    Message_P1() {}

    // 使用COPY深拷贝构造函数
    Message_P1(EC_GROUP *curve, Message_P1 *message)
    {
        user_count_platform = message->user_count_platform;
        P_ = EC_POINT_new(curve);
        EC_POINT_copy(P_, message->P_);
        P = new EC_POINT *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            P[i] = EC_POINT_new(curve);
            EC_POINT_copy(P[i], message->P[i]);
        }
        Z_hat = BN_dup(message->Z_hat);
    }

    // 从string反序列化
    Message_P1(EC_GROUP *curve, std::string message, int user_count_platform, BN_CTX *ctx)
    {
        this->user_count_platform = user_count_platform;
        Messages::Msg_P1 msg_p1;
        msg_p1.ParseFromString(message);
        BN_CTX_start(ctx);
        P_ = EC_POINT_deserialize(curve, msg_p1.p_prime(), ctx);
        P = new EC_POINT *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            P[i] = EC_POINT_deserialize(curve, msg_p1.p(i), ctx);
        }
        Z_hat = BN_deserialize(msg_p1.z_hat());
        BN_CTX_end(ctx);
    }
    // 释放内存
    ~Message_P1()
    {
        if (P_ != nullptr)
        {
            EC_POINT_free(P_);
            P_ = nullptr;
        }
        if (P != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (P[i] != nullptr)
                {
                    EC_POINT_free(P[i]);
                    P[i] = nullptr;
                }
            }
            delete[] P;
            P = nullptr;
        }
        if (Z_hat != nullptr)
        {
            BN_free(Z_hat);
            Z_hat = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        size += EC_POINT_point2oct(curve, P_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        for (int i = 0; i < user_count_platform; i++)
        {
            size += EC_POINT_point2oct(curve, P[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        }
        size += BN_num_bytes(Z_hat);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_P1 msg_p1;
        // 序列化P_, **P, Z_hat
        msg_p1.set_p_prime(EC_POINT_serialize(curve, P_, ctx));
        for (int i = 0; i < user_count_platform; i++)
        {
            msg_p1.add_p(EC_POINT_serialize(curve, P[i], ctx));
        }
        msg_p1.set_z_hat(BN_serialize(Z_hat));
        // 将序列化后的P1写入字符串
        msg_p1.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};

class Message_A2
{
public:
    int user_count_advertiser;
    int user_count_platform;
    ElGamal_ciphertext **C = nullptr;
    ElGamal_ciphertext **C_ = nullptr;
    EC_POINT **CA = nullptr;
    EC_POINT **CB = nullptr;
    EC_POINT **CD_ = nullptr;
    //EC_POINT **A = nullptr;
    BIGNUM *E = nullptr;
    ElGamal_ciphertext *F = nullptr;
    EC_POINT **Q = nullptr;
    EC_POINT *GS_ = nullptr;
    EC_POINT *GS = nullptr;
    EC_POINT *pkA_ = nullptr;
    BIGNUM *skA_hat = nullptr;
    EC_POINT **C1_ = nullptr;
    EC_POINT **C2_ = nullptr;
    BIGNUM **x_hat = nullptr;
    BIGNUM **y_hat = nullptr;

    Message_A2() {}

    // 使用COPY深拷贝构造函数
    Message_A2(EC_GROUP *curve, Message_A2 *message)
    {
        user_count_advertiser = message->user_count_advertiser;
        user_count_platform = message->user_count_platform;
        C = new ElGamal_ciphertext *[user_count_platform];
        C_ = new ElGamal_ciphertext *[user_count_platform];
        CA = new EC_POINT *[user_count_platform];
        CB = new EC_POINT *[user_count_platform];
        CD_ = new EC_POINT *[user_count_platform];
        //A = new EC_POINT *[user_count_advertiser];
        Q = new EC_POINT *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            C[i] = new ElGamal_ciphertext(curve, message->C[i]);
            C_[i] = new ElGamal_ciphertext(curve, message->C_[i]);
            CA[i] = EC_POINT_new(curve);
            CB[i] = EC_POINT_new(curve);
            CD_[i] = EC_POINT_new(curve);
            Q[i] = EC_POINT_new(curve);
            EC_POINT_copy(CA[i], message->CA[i]);
            EC_POINT_copy(CB[i], message->CB[i]);
            EC_POINT_copy(CD_[i], message->CD_[i]);
            EC_POINT_copy(Q[i], message->Q[i]);
        }
        // for (int i = 0; i < user_count_advertiser; i++)
        // {
        //     A[i] = EC_POINT_new(curve);
        //     EC_POINT_copy(A[i], message->A[i]);
        // }
        E = BN_dup(message->E);
        F = new ElGamal_ciphertext(curve, message->F);
        GS_ = EC_POINT_new(curve);
        GS = EC_POINT_new(curve);
        pkA_ = EC_POINT_new(curve);
        skA_hat = BN_dup(message->skA_hat);
        EC_POINT_copy(GS_, message->GS_);
        EC_POINT_copy(GS, message->GS);
        EC_POINT_copy(pkA_, message->pkA_);
        C1_ = new EC_POINT *[user_count_platform];
        C2_ = new EC_POINT *[user_count_platform];
        x_hat = new BIGNUM *[user_count_platform];
        y_hat = new BIGNUM *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            C1_[i] = EC_POINT_new(curve);
            C2_[i] = EC_POINT_new(curve);
            x_hat[i] = BN_dup(message->x_hat[i]);
            y_hat[i] = BN_dup(message->y_hat[i]);
            EC_POINT_copy(C1_[i], message->C1_[i]);
            EC_POINT_copy(C2_[i], message->C2_[i]);
        }
    }

    // 从string反序列化
    Message_A2(EC_GROUP *curve, std::string message, int user_count_advertiser, int user_count_platform, BN_CTX *ctx)
    {
        this->user_count_advertiser = user_count_advertiser;
        this->user_count_platform = user_count_platform;
        Messages::Msg_A2 msg_a2;
        msg_a2.ParseFromString(message);
        C = new ElGamal_ciphertext *[user_count_platform];
        C_ = new ElGamal_ciphertext *[user_count_platform];
        CA = new EC_POINT *[user_count_platform];
        CB = new EC_POINT *[user_count_platform];
        CD_ = new EC_POINT *[user_count_platform];
        //A = new EC_POINT *[user_count_advertiser];
        Q = new EC_POINT *[user_count_platform];
        C1_ = new EC_POINT *[user_count_platform];
        C2_ = new EC_POINT *[user_count_platform];
        x_hat = new BIGNUM *[user_count_platform];
        y_hat = new BIGNUM *[user_count_platform];
        for (int i = 0; i < user_count_platform; i++)
        {
            C[i] = new ElGamal_ciphertext(curve, msg_a2.c(i), ctx);
            C_[i] = new ElGamal_ciphertext(curve, msg_a2.c_prime(i), ctx);
            CA[i] = EC_POINT_deserialize(curve, msg_a2.ca(i), ctx);
            CB[i] = EC_POINT_deserialize(curve, msg_a2.cb(i), ctx);
            CD_[i] = EC_POINT_deserialize(curve, msg_a2.cd_prime(i), ctx);
            Q[i] = EC_POINT_deserialize(curve, msg_a2.q(i), ctx);
            C1_[i] = EC_POINT_deserialize(curve, msg_a2.c1_prime(i), ctx);
            C2_[i] = EC_POINT_deserialize(curve, msg_a2.c2_prime(i), ctx);
            x_hat[i] = BN_deserialize(msg_a2.x_hat(i));
            y_hat[i] = BN_deserialize(msg_a2.y_hat(i));
        }
        // for (int i = 0; i < user_count_advertiser; i++)
        // {
        //     A[i] = EC_POINT_deserialize(curve, msg_a2.a(i), ctx);
        // }
        E = BN_deserialize(msg_a2.e());
        F = new ElGamal_ciphertext(curve, msg_a2.f(), ctx);
        GS_ = EC_POINT_deserialize(curve, msg_a2.gs_prime(), ctx);
        GS = EC_POINT_deserialize(curve, msg_a2.gs(), ctx);
        pkA_ = EC_POINT_deserialize(curve, msg_a2.pka_prime(), ctx);
        skA_hat = BN_deserialize(msg_a2.ska_hat());
    }

    // 释放内存
    ~Message_A2()
    {
        if (C != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C[i] != nullptr)
                {
                    delete C[i];
                    C[i] = nullptr;
                }
            }
            delete[] C;
            C = nullptr;
        }
        if (C_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C_[i] != nullptr)
                {
                    delete C_[i];
                    C_[i] = nullptr;
                }
            }
            delete[] C_;
            C_ = nullptr;
        }
        if (CA != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CA[i] != nullptr)
                {
                    EC_POINT_free(CA[i]);
                    CA[i] = nullptr;
                }
            }
            delete[] CA;
            CA = nullptr;
        }
        if (CB != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CB[i] != nullptr)
                {
                    EC_POINT_free(CB[i]);
                    CB[i] = nullptr;
                }
            }
            delete[] CB;
            CB = nullptr;
        }
        if (CD_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (CD_[i] != nullptr)
                {
                    EC_POINT_free(CD_[i]);
                    CD_[i] = nullptr;
                }
            }
            delete[] CD_;
            CD_ = nullptr;
        }
        // if (A != nullptr)
        // {
        //     for (int i = 0; i < user_count_advertiser; i++)
        //     {
        //         if (A[i] != nullptr)
        //         {
        //             EC_POINT_free(A[i]);
        //             A[i] = nullptr;
        //         }
        //     }
        //     delete[] A;
        //     A = nullptr;
        // }
        if (E != nullptr)
        {
            BN_free(E);
            E = nullptr;
        }
        if (F != nullptr)
        {
            delete F;
            F = nullptr;
        }
        if (Q != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (Q[i] != nullptr)
                {
                    EC_POINT_free(Q[i]);
                    Q[i] = nullptr;
                }
            }
            delete[] Q;
            Q = nullptr;
        }
        // 释放GS_,GS,pkA_,skA_hat
        if (GS_ != nullptr)
        {
            EC_POINT_free(GS_);
            GS_ = nullptr;
        }
        if (GS != nullptr)
        {
            EC_POINT_free(GS);
            GS = nullptr;
        }
        if (pkA_ != nullptr)
        {
            EC_POINT_free(pkA_);
            pkA_ = nullptr;
        }
        if (skA_hat != nullptr)
        {
            BN_free(skA_hat);
            skA_hat = nullptr;
        }
        if (C1_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C1_[i] != nullptr)
                {
                    EC_POINT_free(C1_[i]);
                    C1_[i] = nullptr;
                }
            }
            delete[] C1_;
            C1_ = nullptr;
        }
        if (C2_ != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (C2_[i] != nullptr)
                {
                    EC_POINT_free(C2_[i]);
                    C2_[i] = nullptr;
                }
            }
            delete[] C2_;
            C2_ = nullptr;
        }
        if (x_hat != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (x_hat[i] != nullptr)
                {
                    BN_free(x_hat[i]);
                    x_hat[i] = nullptr;
                }
            }
            delete[] x_hat;
            x_hat = nullptr;
        }
        if (y_hat != nullptr)
        {
            for (int i = 0; i < user_count_platform; i++)
            {
                if (y_hat[i] != nullptr)
                {
                    BN_free(y_hat[i]);
                    y_hat[i] = nullptr;
                }
            }
            delete[] y_hat;
            y_hat = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        // 计算C,C_,CA,CB,CD_,A,E,F,Q,GS_,GS,pkA_,skA_hat的字节数
        size += EC_POINT_point2oct(curve, GS_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GS, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pkA_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(skA_hat, NULL);
        size += BN_bn2mpi(E, NULL);
        size += F->get_size(curve, ctx);
        for (int j = 0; j < user_count_platform; j++)
        {
            size += C[j]->get_size(curve, ctx);
            size += C_[j]->get_size(curve, ctx);
            size += EC_POINT_point2oct(curve, CA[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CB[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CD_[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, Q[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        }
        // for (int i = 0; i < user_count_advertiser; i++)
        // {
        //     size += EC_POINT_point2oct(curve, A[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        // }
        // 计算C_1,C_2,x_hat,y_hat的字节数
        for (int j = 0; j < user_count_platform; j++)
        {
            size += EC_POINT_point2oct(curve, C1_[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, C2_[j], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += BN_bn2mpi(x_hat[j], NULL);
            size += BN_bn2mpi(y_hat[j], NULL);
        }
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_A2 msg_a2;
        // 将C,C_,CA,CB,CD_,A,E,F,Q,GS_,GS,pkA_,skA_hat,C1_,C2_,x_hat,y_hat序列化
        for (int j = 0; j < user_count_platform; j++)
        {
            C[j]->insert(curve, msg_a2.add_c(), ctx);
            C_[j]->insert(curve, msg_a2.add_c_prime(), ctx);
            msg_a2.add_ca(EC_POINT_serialize(curve, CA[j], ctx));
            msg_a2.add_cb(EC_POINT_serialize(curve, CB[j], ctx));
            msg_a2.add_cd_prime(EC_POINT_serialize(curve, CD_[j], ctx));
            msg_a2.add_q(EC_POINT_serialize(curve, Q[j], ctx));
            msg_a2.add_c1_prime(EC_POINT_serialize(curve, C1_[j], ctx));
            msg_a2.add_c2_prime(EC_POINT_serialize(curve, C2_[j], ctx));
            msg_a2.add_x_hat(BN_serialize(x_hat[j]));
            msg_a2.add_y_hat(BN_serialize(y_hat[j]));
        }
        // for (int i = 0; i < user_count_advertiser; i++)
        // {
        //     msg_a2.add_a(EC_POINT_serialize(curve, A[i], ctx));
        // }
        msg_a2.set_e(BN_serialize(E));
        F->insert(curve, msg_a2.mutable_f(), ctx);
        msg_a2.set_gs(EC_POINT_serialize(curve, GS, ctx));
        msg_a2.set_gs_prime(EC_POINT_serialize(curve, GS_, ctx));
        msg_a2.set_pka_prime(EC_POINT_serialize(curve, pkA_, ctx));
        msg_a2.set_ska_hat(BN_serialize(skA_hat));

        // 将序列化后的A2写入字符串
        msg_a2.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};

class Message_P3
{
public:
    int user_count_advertiser;
    int user_count_platform;
    EC_POINT **L = nullptr;
    //BIGNUM *k2_hat = nullptr;
    //EC_POINT *C2 = nullptr;
    //EC_POINT *C2_ = nullptr;
    EC_POINT *C3 = nullptr;
    EC_POINT *C3_ = nullptr;
    BIGNUM *kq_hat = nullptr;
    //EC_POINT *Q_ = nullptr;
    EC_POINT *A_ = nullptr;

    Message_P3() {}

    // 使用COPY深拷贝构造函数
    Message_P3(EC_GROUP *curve, Message_P3 *message)
    {
        user_count_advertiser = message->user_count_advertiser;
        user_count_platform = message->user_count_platform;
        L = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            L[i] = EC_POINT_new(curve);
            EC_POINT_copy(L[i], message->L[i]);
        }
        // k2_hat = BN_dup(message->k2_hat);
        // C2 = EC_POINT_new(curve);
        // C2_ = EC_POINT_new(curve);
        C3 = EC_POINT_new(curve);
        C3_ = EC_POINT_new(curve);
        kq_hat = BN_dup(message->kq_hat);
        //Q_ = EC_POINT_new(curve);
        A_ = EC_POINT_new(curve);
        // EC_POINT_copy(C2, message->C2);
        // EC_POINT_copy(C2_, message->C2_);
        EC_POINT_copy(C3, message->C3);
        EC_POINT_copy(C3_, message->C3_);
        //EC_POINT_copy(Q_, message->Q_);
        EC_POINT_copy(A_, message->A_);
    }

    // 从string反序列化
    Message_P3(EC_GROUP *curve, std::string message, int user_count_advertiser, int user_count_platform, BN_CTX *ctx)
    {
        this->user_count_advertiser = user_count_advertiser;
        this->user_count_platform = user_count_platform;
        Messages::Msg_P3 msg_p3;
        msg_p3.ParseFromString(message);
        L = new EC_POINT *[user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            L[i] = EC_POINT_deserialize(curve, msg_p3.l(i), ctx);
        }
        // k2_hat = BN_deserialize(msg_p3.k2_hat());
        // C2 = EC_POINT_deserialize(curve, msg_p3.c2(), ctx);
        // C2_ = EC_POINT_deserialize(curve, msg_p3.c2_prime(), ctx);
        C3 = EC_POINT_deserialize(curve, msg_p3.c3(), ctx);
        C3_ = EC_POINT_deserialize(curve, msg_p3.c3_prime(), ctx);
        kq_hat = BN_deserialize(msg_p3.kq_hat());
        //Q_ = EC_POINT_deserialize(curve, msg_p3.q_prime(), ctx);
        A_ = EC_POINT_deserialize(curve, msg_p3.a_prime(), ctx);
    }

    // 释放内存
    ~Message_P3()
    {
        if (L != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (L[i] != nullptr)
                {
                    EC_POINT_free(L[i]);
                    L[i] = nullptr;
                }
            }
            delete[] L;
            L = nullptr;
        }
        // if (k2_hat != nullptr)
        // {
        //     BN_free(k2_hat);
        //     k2_hat = nullptr;
        // }
        // if (C2 != nullptr)
        // {
        //     EC_POINT_free(C2);
        //     C2 = nullptr;
        // }
        // if (C2_ != nullptr)
        // {
        //     EC_POINT_free(C2_);
        //     C2_ = nullptr;
        // }
        if (C3 != nullptr)
        {
            EC_POINT_free(C3);
            C3 = nullptr;
        }
        if (C3_ != nullptr)
        {
            EC_POINT_free(C3_);
            C3_ = nullptr;
        }
        if (kq_hat != nullptr)
        {
            BN_free(kq_hat);
            kq_hat = nullptr;
        }
        // if (Q_ != nullptr)
        // {
        //     EC_POINT_free(Q_);
        //     Q_ = nullptr;
        // }
        if (A_ != nullptr)
        {
            EC_POINT_free(A_);
            A_ = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        for (int i = 0; i < user_count_advertiser; i++)
        {
            size += EC_POINT_point2oct(curve, L[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        }
        // size += BN_bn2mpi(k2_hat, NULL);
        // size += EC_POINT_point2oct(curve, C2, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        // size += EC_POINT_point2oct(curve, C2_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C3, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, C3_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(kq_hat, NULL);
        //size += EC_POINT_point2oct(curve, Q_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, A_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_P3 msg_p3;
        for (int i = 0; i < user_count_advertiser; i++)
        {
            msg_p3.add_l(EC_POINT_serialize(curve, L[i], ctx));
        }
        // msg_p3.set_k2_hat(BN_serialize(k2_hat));
        // msg_p3.set_c2(EC_POINT_serialize(curve, C2, ctx));
        // msg_p3.set_c2_prime(EC_POINT_serialize(curve, C2_, ctx));
        msg_p3.set_c3(EC_POINT_serialize(curve, C3, ctx));
        msg_p3.set_c3_prime(EC_POINT_serialize(curve, C3_, ctx));
        msg_p3.set_kq_hat(BN_serialize(kq_hat));
        //msg_p3.set_q_prime(EC_POINT_serialize(curve, Q_, ctx));
        msg_p3.set_a_prime(EC_POINT_serialize(curve, A_, ctx));
        msg_p3.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};

class Message_P3_
{
public:
    int user_count_advertiser;
    int user_count_platform;
    EC_POINT **L = nullptr;
    //BIGNUM *k2_hat = nullptr;
    BIGNUM *sk_p_hat = nullptr;
    //EC_POINT *C2 = nullptr;
    //EC_POINT *C2_ = nullptr;
    EC_POINT **Ct1_ = nullptr;
    EC_POINT **Ct2_ = nullptr;
    BIGNUM **x_hat_ = nullptr;
    BIGNUM **y_hat_ = nullptr;
    ElGamal_ciphertext **Ct = nullptr;
    ElGamal_ciphertext **Ct_ = nullptr;
    EC_POINT **CA_ = nullptr;
    EC_POINT **CB_ = nullptr;
    EC_POINT **CD__ = nullptr;
    BIGNUM *E_ = nullptr;
    ElGamal_ciphertext *F_ = nullptr;
    ElGamal_ciphertext *F__ = nullptr;
    EC_POINT *GSP = nullptr;
    EC_POINT *GSP_ = nullptr;
    EC_POINT *pk_p_ = nullptr;
    EC_POINT *pk_p = nullptr;

    //EC_POINT *Q_ = nullptr;
    ElGamal_ciphertext **V_ = nullptr;

    Message_P3_() {}

    // 使用COPY深拷贝构造函数
    Message_P3_(EC_GROUP *curve, Message_P3_ *message)
    {
        user_count_advertiser = message->user_count_advertiser;
        user_count_platform = message->user_count_platform;
        V_ = new ElGamal_ciphertext *[user_count_advertiser];
        Ct = new ElGamal_ciphertext *[user_count_advertiser];
        Ct_ = new ElGamal_ciphertext *[user_count_advertiser];
        L = new EC_POINT *[user_count_advertiser];
        Ct1_ = new EC_POINT *[user_count_advertiser];
        Ct2_ = new EC_POINT *[user_count_advertiser];
        CA_ = new EC_POINT *[user_count_advertiser];
        CB_ = new EC_POINT *[user_count_advertiser];
        CD__ = new EC_POINT *[user_count_advertiser];
        x_hat_ = new BIGNUM * [user_count_advertiser];
        y_hat_ = new BIGNUM * [user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {
            V_[i] = new ElGamal_ciphertext(curve, message->V_[i]);
            Ct[i] = new ElGamal_ciphertext(curve, message->Ct[i]);
            Ct_[i] = new ElGamal_ciphertext(curve, message->Ct_[i]);
            x_hat_[i] = BN_dup(message->x_hat_[i]);
            y_hat_[i] = BN_dup(message->y_hat_[i]);
            L[i] = EC_POINT_new(curve);
            EC_POINT_copy(L[i], message->L[i]);
            Ct1_[i] = EC_POINT_new(curve);
            EC_POINT_copy(Ct1_[i], message->Ct1_[i]);
            Ct2_[i] = EC_POINT_new(curve);
            EC_POINT_copy(Ct2_[i], message->Ct2_[i]);
            CA_[i] = EC_POINT_new(curve);
            EC_POINT_copy(CA_[i], message->CA_[i]);
            CB_[i] = EC_POINT_new(curve);
            EC_POINT_copy(CB_[i], message->CB_[i]);
            CD__[i] = EC_POINT_new(curve);
            EC_POINT_copy(CD__[i], message->CD__[i]);

        }

        F_ = new ElGamal_ciphertext(curve, message->F_);
        F__ = new ElGamal_ciphertext(curve, message->F__);

        //k2_hat = BN_dup(message->k2_hat);
        sk_p_hat = BN_dup(message->sk_p_hat);
        E_ = BN_dup(message->E_);

        //C2 = EC_POINT_new(curve);
        //C2_ = EC_POINT_new(curve);
        //Q_ = EC_POINT_new(curve);
        GSP = EC_POINT_new(curve);
        GSP_ = EC_POINT_new(curve);
        pk_p = EC_POINT_new(curve);
        pk_p_ = EC_POINT_new(curve);
        //EC_POINT_copy(C2, message->C2);
        //EC_POINT_copy(C2_, message->C2_);
        //EC_POINT_copy(Q_, message->Q_);
        EC_POINT_copy(GSP, message->GSP);
        EC_POINT_copy(GSP_, message->GSP_);
        EC_POINT_copy(pk_p, message->pk_p);
        EC_POINT_copy(pk_p_, message->pk_p_);
    }

    // 从string反序列化
    Message_P3_(EC_GROUP *curve, std::string message, int user_count_advertiser, int user_count_platform, BN_CTX *ctx)
    {
        this->user_count_advertiser = user_count_advertiser;
        this->user_count_platform = user_count_platform;
        Messages::Msg_P3_ msg_p3_;
        msg_p3_.ParseFromString(message);
        L = new EC_POINT *[user_count_advertiser];
        Ct1_ = new EC_POINT *[user_count_advertiser];
        Ct2_ = new EC_POINT *[user_count_advertiser];
        CA_ = new EC_POINT *[user_count_advertiser];
        CB_ = new EC_POINT *[user_count_advertiser];
        CD__ = new EC_POINT *[user_count_advertiser];
        V_ = new ElGamal_ciphertext *[user_count_advertiser];
        Ct = new ElGamal_ciphertext *[user_count_advertiser];
        Ct_ = new ElGamal_ciphertext *[user_count_advertiser];
        x_hat_ = new BIGNUM * [user_count_advertiser];
        y_hat_ = new BIGNUM * [user_count_advertiser];
        for (int i = 0; i < user_count_advertiser; i++)
        {   
            Ct[i] = new ElGamal_ciphertext(curve,msg_p3_.ct(i),ctx);
            Ct_[i] = new ElGamal_ciphertext(curve,msg_p3_.ct_prime(i),ctx);
            V_[i] = new ElGamal_ciphertext(curve,msg_p3_.v_(i),ctx);
            x_hat_[i] = BN_deserialize(msg_p3_.x_hat_(i));
            y_hat_[i] = BN_deserialize(msg_p3_.y_hat_(i));
            L[i] = EC_POINT_deserialize(curve, msg_p3_.l(i), ctx);
            Ct1_[i] = EC_POINT_deserialize(curve, msg_p3_.ct1_(i), ctx);
            Ct2_[i] = EC_POINT_deserialize(curve, msg_p3_.ct2_(i), ctx);
            CA_[i] = EC_POINT_deserialize(curve, msg_p3_.ca_(i), ctx);
            CB_[i] = EC_POINT_deserialize(curve, msg_p3_.cb_(i), ctx);
            CD__[i] = EC_POINT_deserialize(curve, msg_p3_.cd__(i), ctx);
        }

        F_ = new ElGamal_ciphertext(curve, msg_p3_.f_(),ctx);
        F__ = new ElGamal_ciphertext(curve, msg_p3_.f_prime_(),ctx);

        //k2_hat = BN_deserialize(msg_p3_.k2_hat());
        sk_p_hat = BN_deserialize(msg_p3_.sk_p_hat());
        E_ = BN_deserialize(msg_p3_.e_());
        //C2 = EC_POINT_deserialize(curve, msg_p3_.c2(), ctx);
        //C2_ = EC_POINT_deserialize(curve, msg_p3_.c2_prime(), ctx);
        //Q_ = EC_POINT_deserialize(curve, msg_p3_.q_prime(), ctx);
        GSP = EC_POINT_deserialize(curve, msg_p3_.gsp(), ctx);
        GSP_ = EC_POINT_deserialize(curve, msg_p3_.gsp_prime(), ctx);
        pk_p = EC_POINT_deserialize(curve, msg_p3_.pk_p(), ctx);
        pk_p_ = EC_POINT_deserialize(curve, msg_p3_.pk_p_prime(), ctx);
    }

    // 释放内存
    ~Message_P3_()
    {
        if (L != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (L[i] != nullptr)
                {
                    EC_POINT_free(L[i]);
                    L[i] = nullptr;
                }
            }
            delete[] L;
            L = nullptr;
        }
        if (Ct1_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (Ct1_[i] != nullptr)
                {
                    EC_POINT_free(Ct1_[i]);
                    Ct1_[i] = nullptr;
                }
            }
            delete[] Ct1_;
            Ct1_ = nullptr;
        }
        if (Ct2_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (Ct2_[i] != nullptr)
                {
                    EC_POINT_free(Ct2_[i]);
                    Ct2_[i] = nullptr;
                }
            }
            delete[] Ct2_;
            Ct2_ = nullptr;
        }
        if (CA_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (CA_[i] != nullptr)
                {
                    EC_POINT_free(CA_[i]);
                    CA_[i] = nullptr;
                }
            }
            delete[] CA_;
            CA_ = nullptr;
        }
        if (CB_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (CB_[i] != nullptr)
                {
                    EC_POINT_free(CB_[i]);
                    CB_[i] = nullptr;
                }
            }
            delete[] CB_;
            CB_ = nullptr;
        }
        if (CD__ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (CD__[i] != nullptr)
                {
                    EC_POINT_free(CD__[i]);
                    CD__[i] = nullptr;
                }
            }
            delete[] CD__;
            CD__ = nullptr;
        }
        if (V_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (V_[i] != nullptr)
                {
                    delete V_[i];
                    V_[i] = nullptr;
                }
            }
            delete[] V_;
            V_ = nullptr;
        }
        if (Ct != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (Ct[i] != nullptr)
                {
                    delete Ct[i];
                    Ct[i] = nullptr;
                }
            }
            delete[] Ct;
            Ct = nullptr;
        }
        if (Ct_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (Ct_[i] != nullptr)
                {
                    delete Ct_[i];
                    Ct_[i] = nullptr;
                }
            }
            delete[] Ct_;
            Ct_ = nullptr;
        }
        if (x_hat_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (x_hat_[i] != nullptr)
                {
                    BN_free(x_hat_[i]);
                    x_hat_[i] = nullptr;
                }
            }
            delete[] x_hat_;
            x_hat_ = nullptr;
        }
        if (y_hat_ != nullptr)
        {
            for (int i = 0; i < user_count_advertiser; i++)
            {
                if (y_hat_[i] != nullptr)
                {
                    BN_free(y_hat_[i]);
                    y_hat_[i] = nullptr;
                }
            }
            delete[] y_hat_;
            y_hat_ = nullptr;
        }
        if (F_ != nullptr)
        {
            delete F_;
            F_ = nullptr;
        }
        if (F__ != nullptr)
        {
            delete F__;
            F__ = nullptr;
        }
        // if (k2_hat != nullptr)
        // {
        //     BN_free(k2_hat);
        //     k2_hat = nullptr;
        // }
        if (sk_p_hat != nullptr)
        {
            BN_free(sk_p_hat);
            sk_p_hat = nullptr;
        }
        if (E_ != nullptr)
        {
            BN_free(E_);
            E_ = nullptr;
        }
        // if (C2 != nullptr)
        // {
        //     EC_POINT_free(C2);
        //     C2 = nullptr;
        // }
        // if (C2_ != nullptr)
        // {
        //     EC_POINT_free(C2_);
        //     C2_ = nullptr;
        // }
        // if (Q_ != nullptr)
        // {
        //     EC_POINT_free(Q_);
        //     Q_ = nullptr;
        // }
        if (GSP != nullptr)
        {
            EC_POINT_free(GSP);
            GSP = nullptr;
        }
        if (GSP_ != nullptr)
        {
            EC_POINT_free(GSP_);
            GSP_ = nullptr;
        }
        if (pk_p != nullptr)
        {
            EC_POINT_free(pk_p);
            pk_p = nullptr;
        }
        if (pk_p_ != nullptr)
        {
            EC_POINT_free(pk_p_);
            pk_p_ = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        for (int i = 0; i < user_count_advertiser; i++)
        {   
            size += V_[i]->get_size(curve, ctx);
            size += Ct[i]->get_size(curve, ctx);
            size += Ct_[i]->get_size(curve, ctx);
            size += BN_bn2mpi(x_hat_[i], NULL);
            size += BN_bn2mpi(y_hat_[i], NULL);
            size += EC_POINT_point2oct(curve, L[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, Ct1_[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, Ct2_[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CA_[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CB_[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
            size += EC_POINT_point2oct(curve, CD__[i], POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        }
        size += F_->get_size(curve, ctx);
        size += F__->get_size(curve, ctx);
        //size += BN_bn2mpi(k2_hat, NULL);
        size += BN_bn2mpi(sk_p_hat, NULL);
        size += BN_bn2mpi(E_, NULL);
        //size += EC_POINT_point2oct(curve, C2, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        //size += EC_POINT_point2oct(curve, C2_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        //size += EC_POINT_point2oct(curve, Q_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GSP, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GSP_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pk_p, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pk_p_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_P3_ msg_p3_;
        for (int i = 0; i < user_count_advertiser; i++)
        {
            msg_p3_.add_l(EC_POINT_serialize(curve, L[i], ctx));
            msg_p3_.add_ct1_(EC_POINT_serialize(curve, Ct1_[i], ctx));
            msg_p3_.add_ct2_(EC_POINT_serialize(curve, Ct2_[i], ctx));
            msg_p3_.add_ca_(EC_POINT_serialize(curve, CA_[i], ctx));
            msg_p3_.add_cb_(EC_POINT_serialize(curve, CB_[i], ctx));
            msg_p3_.add_cd__(EC_POINT_serialize(curve, CD__[i], ctx));
            V_[i]->insert(curve, msg_p3_.add_v_(), ctx);
            Ct[i]->insert(curve, msg_p3_.add_ct(), ctx);
            Ct_[i]->insert(curve, msg_p3_.add_ct_prime(), ctx);
            msg_p3_.add_x_hat_(BN_serialize(x_hat_[i]));
            msg_p3_.add_y_hat_(BN_serialize(y_hat_[i]));
        }
        F_->insert(curve, msg_p3_.mutable_f_(), ctx);
        F__->insert(curve, msg_p3_.mutable_f_prime_(), ctx);
        //msg_p3_.set_k2_hat(BN_serialize(k2_hat));
        msg_p3_.set_e_(BN_serialize(E_));
        msg_p3_.set_sk_p_hat(BN_serialize(sk_p_hat));
        //msg_p3_.set_c2(EC_POINT_serialize(curve, C2, ctx));
        //msg_p3_.set_c2_prime(EC_POINT_serialize(curve, C2_, ctx));
        //msg_p3_.set_q_prime(EC_POINT_serialize(curve, Q_, ctx));
        msg_p3_.set_gsp(EC_POINT_serialize(curve, GSP, ctx));
        msg_p3_.set_gsp_prime(EC_POINT_serialize(curve, GSP_, ctx));
        msg_p3_.set_pk_p(EC_POINT_serialize(curve, pk_p, ctx));
        msg_p3_.set_pk_p_prime(EC_POINT_serialize(curve, pk_p_, ctx));
        msg_p3_.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};


class Message_A4
{
public:
    BIGNUM *Sum = nullptr;
    EC_POINT *GK = nullptr;
    EC_POINT *GK_ = nullptr;
    EC_POINT *pkA__ = nullptr;
    BIGNUM *skA_hat_ = nullptr;
    ElGamal_ciphertext *Sum_E = nullptr;
    Message_A4() {}

    // 使用COPY深拷贝构造函数
    Message_A4(EC_GROUP *curve, Message_A4 *message)
    {
        Sum = BN_dup(message->Sum);
        GK = EC_POINT_new(curve);
        GK_ = EC_POINT_new(curve);
        pkA__ = EC_POINT_new(curve);
        skA_hat_ = BN_dup(message->skA_hat_);
        EC_POINT_copy(GK, message->GK);
        EC_POINT_copy(GK_, message->GK_);
        EC_POINT_copy(pkA__, message->pkA__);
        Sum_E = new ElGamal_ciphertext(curve, message->Sum_E);

    }

    // 从string反序列化
    Message_A4(EC_GROUP *curve, std::string message, BN_CTX *ctx)
    {
        Messages::Msg_A4 msg_a4;
        msg_a4.ParseFromString(message);
        Sum = BN_deserialize(msg_a4.sum());
        GK = EC_POINT_deserialize(curve, msg_a4.gk(), ctx);
        GK_ = EC_POINT_deserialize(curve, msg_a4.gk_prime(), ctx);
        pkA__ = EC_POINT_deserialize(curve, msg_a4.pka_prime_prime(), ctx);
        skA_hat_ = BN_deserialize(msg_a4.ska_hat_prime());
        Sum_E = new ElGamal_ciphertext(curve, msg_a4.sum_e(),ctx);

    }

    // 释放内存
    ~Message_A4()
    {
        if (Sum != nullptr)
        {
            BN_free(Sum);
            Sum = nullptr;
        }
        if (GK != nullptr)
        {
            EC_POINT_free(GK);
            GK = nullptr;
        }
        if (GK_ != nullptr)
        {
            EC_POINT_free(GK_);
            GK_ = nullptr;
        }
        if (pkA__ != nullptr)
        {
            EC_POINT_free(pkA__);
            pkA__ = nullptr;
        }
        if (skA_hat_ != nullptr)
        {
            BN_free(skA_hat_);
            skA_hat_ = nullptr;
        }
        if (Sum_E != nullptr)
        {
            delete Sum_E;
            Sum_E = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        if (Sum != nullptr)
        {
            size += BN_bn2mpi(Sum, NULL);
        }
        size += Sum_E->get_size(curve, ctx);
        size += EC_POINT_point2oct(curve, GK, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GK_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pkA__, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(skA_hat_, NULL);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_A4 msg_a4;
        if (Sum != nullptr)
        {
            msg_a4.set_sum(BN_serialize(Sum));
        }
        else
        {
            BIGNUM *zero = BN_new();
            BN_zero(zero);
            msg_a4.set_sum(BN_serialize(zero));
            BN_free(zero);
        }
        Sum_E->insert(curve, msg_a4.mutable_sum_e(), ctx);
        msg_a4.set_gk(EC_POINT_serialize(curve, GK, ctx));
        msg_a4.set_gk_prime(EC_POINT_serialize(curve, GK_, ctx));
        msg_a4.set_pka_prime_prime(EC_POINT_serialize(curve, pkA__, ctx));
        msg_a4.set_ska_hat_prime(BN_serialize(skA_hat_));
        msg_a4.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};

class Message_A4_
{
public:
    BIGNUM *Sum = nullptr;
    EC_POINT *GK = nullptr;
    EC_POINT *GK_ = nullptr;
    EC_POINT *pkA__ = nullptr;
    BIGNUM *skA_hat_ = nullptr;
    ElGamal_ciphertext *Sum_E = nullptr;

    Message_A4_() {}

    // 使用COPY深拷贝构造函数
    Message_A4_(EC_GROUP *curve, Message_A4_ *message)
    {
        Sum = BN_dup(message->Sum);
        GK = EC_POINT_new(curve);
        GK_ = EC_POINT_new(curve);
        pkA__ = EC_POINT_new(curve);
        skA_hat_ = BN_dup(message->skA_hat_);
        EC_POINT_copy(GK, message->GK);
        EC_POINT_copy(GK_, message->GK_);
        EC_POINT_copy(pkA__, message->pkA__);
        Sum_E = new ElGamal_ciphertext(curve, message->Sum_E);
    }

    // 从string反序列化
    Message_A4_(EC_GROUP *curve, std::string message, BN_CTX *ctx)
    {
        Messages::Msg_A4_ msg_a4;
        msg_a4.ParseFromString(message);
        Sum = BN_deserialize(msg_a4.sum());
        GK = EC_POINT_deserialize(curve, msg_a4.gk(), ctx);
        GK_ = EC_POINT_deserialize(curve, msg_a4.gk_prime(), ctx);
        pkA__ = EC_POINT_deserialize(curve, msg_a4.pka_prime_prime(), ctx);
        skA_hat_ = BN_deserialize(msg_a4.ska_hat_prime());
        Sum_E = new ElGamal_ciphertext(curve, msg_a4.sum_e(),ctx);
    }

    // 释放内存
    ~Message_A4_()
    {
        if (Sum != nullptr)
        {
            BN_free(Sum);
            Sum = nullptr;
        }
        if (GK != nullptr)
        {
            EC_POINT_free(GK);
            GK = nullptr;
        }
        if (GK_ != nullptr)
        {
            EC_POINT_free(GK_);
            GK_ = nullptr;
        }
        if (pkA__ != nullptr)
        {
            EC_POINT_free(pkA__);
            pkA__ = nullptr;
        }
        if (skA_hat_ != nullptr)
        {
            BN_free(skA_hat_);
            skA_hat_ = nullptr;
        }
        if (Sum_E != nullptr)
        {
            delete Sum_E;
            Sum_E = nullptr;
        }
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        size_t size = 0;
        if (Sum != nullptr)
        {
            size += BN_bn2mpi(Sum, NULL);
        }
        size += Sum_E->get_size(curve, ctx);
        size += EC_POINT_point2oct(curve, GK, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, GK_, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += EC_POINT_point2oct(curve, pkA__, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        size += BN_bn2mpi(skA_hat_, NULL);
        BN_CTX_end(ctx);
        return size;
    }

    // 序列化
    std::string serialize(EC_GROUP *curve, BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::string output;
        Messages::Msg_A4_ msg_a4;
        if (Sum != nullptr)
        {
            msg_a4.set_sum(BN_serialize(Sum));
        }
        else
        {
            BIGNUM *zero = BN_new();
            BN_zero(zero);
            msg_a4.set_sum(BN_serialize(zero));
            BN_free(zero);
        }
        Sum_E->insert(curve, msg_a4.mutable_sum_e(), ctx);
        msg_a4.set_gk(EC_POINT_serialize(curve, GK, ctx));
        msg_a4.set_gk_prime(EC_POINT_serialize(curve, GK_, ctx));
        msg_a4.set_pka_prime_prime(EC_POINT_serialize(curve, pkA__, ctx));
        msg_a4.set_ska_hat_prime(BN_serialize(skA_hat_));
        msg_a4.SerializeToString(&output);
        BN_CTX_end(ctx);
        return output;
    }
};