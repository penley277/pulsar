#include "common.bpf.h"
#include "network.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("classifier")
int tc_ingress(struct __sk_buff *sk)
{
	return TC_ACT_OK;
}