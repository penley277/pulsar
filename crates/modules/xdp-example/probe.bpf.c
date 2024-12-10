#include "common.bpf.h"
#include "interest_tracking.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//SEC("xdp")
//int xdp_prog(struct xdp_md *ctx) {
//    return XDP_PASS;
//}

#define MAX_LEN 128

// 用于存储统计信息的 PERCPU 数组
struct bpf_map_def_aya SEC("maps") PACKET_STATS = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(long),
    .max_entries = 1,
};

// eBPF 程序
SEC("xdp")
int xdp_bandwidth(struct __sk_buff *skb) {
    // 获取每个包的长度
    int key = 0;
    long *bytes_in = bpf_map_lookup_elem(&PACKET_STATS, &key);

    if (bytes_in) {
        // 累加包的字节数
        __sync_fetch_and_add(bytes_in, skb->len);
    }

    return XDP_PASS;  // 允许数据包通过
}