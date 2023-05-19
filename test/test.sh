# 执行build/bin/main，并解析json输出

# 1 1024 4096 16384 65536 262144 1048576

# 删除result.log
rm -rf ./result.log

# 循环遍历数组，并作为main的参数
for thread in 0 1
do
    echo -e "\n==== Threads: $thread ====\n" >> ./result.log
    # 循环遍历input_size数组
    for i in 1048576 262144 65536 16384 4096 1024  1
    do
        # 执行main，并将输出结果保存到变量result
        result=$(../build/bin/main $i $thread)
        # 使用jq解析result，并输出打印
        input_size=$(echo $result | jq .input_size)
        evidence_gen=$(echo $result | jq .data.time.evidence_gen)
        prove_gen=$(echo $result | jq .data.time.prove_gen)
        prove_verify=$(echo $result | jq .data.time.prove_verify)
        psi_time=$(echo $result | jq .data.time.psi)
        evidence=$(echo $result | jq .data.size.evidence)
        proof=$(echo $result | jq .data.size.proof)
        psi_size=$(echo $result | jq .data.size.psi)
        asd=$(echo $result)
        echo -e "$asd\n$input_size\n$evidence_gen\n$prove_gen\n$prove_verify\n$psi_time\n$evidence\n$proof\n$psi_size\n" >> ./result.log

    done
done