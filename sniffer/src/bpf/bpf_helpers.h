#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/bpf.h>
#include <linux/types.h>

/* Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* Helper macros to define maps */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/*
 * Helper functions
 */

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) 1; // BPF_FUNC_map_lookup_elem
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
	(void *) 2; // BPF_FUNC_map_update_elem
static long (*bpf_map_delete_elem)(void *map, const void *key) =
	(void *) 3; // BPF_FUNC_map_delete_elem
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) =
	(void *) 25; // BPF_FUNC_perf_event_output
static __u64 (*bpf_ktime_get_ns)(void) =
	(void *) 5; // BPF_FUNC_ktime_get_ns

/* LLVM built-in functions that an eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#endif
