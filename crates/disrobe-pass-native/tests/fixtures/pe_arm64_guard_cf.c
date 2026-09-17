typedef int (*Probe)(int);

extern void *__guard_fids_table[];
extern unsigned long __guard_fids_count;
extern unsigned long __guard_flags;
extern void *__guard_longjmp_table[];
extern unsigned long __guard_longjmp_count;

typedef struct {
    unsigned long size;
    unsigned long timestamp;
    unsigned short major_version;
    unsigned short minor_version;
    unsigned long global_flags_clear;
    unsigned long global_flags_set;
    unsigned long critical_section_timeout;
    unsigned long long decommit_free_threshold;
    unsigned long long decommit_total_threshold;
    unsigned long long lock_prefix_table;
    unsigned long long maximum_allocation_size;
    unsigned long long virtual_memory_threshold;
    unsigned long long process_affinity_mask;
    unsigned long process_heap_flags;
    unsigned short service_pack_version;
    unsigned short dependent_load_flags;
    unsigned long long edit_list;
    unsigned long long security_cookie;
    unsigned long long se_handler_table;
    unsigned long long se_handler_count;
    unsigned long long guard_cf_check_function_pointer;
    unsigned long long guard_cf_dispatch_function_pointer;
    unsigned long long guard_cf_function_table;
    unsigned long long guard_cf_function_count;
    unsigned long long guard_flags;
    unsigned long long code_integrity_tail;
    unsigned long long guard_address_taken_iat_entry_table;
    unsigned long long guard_address_taken_iat_entry_count;
    unsigned long long guard_long_jump_target_table;
    unsigned long long guard_long_jump_target_count;
} LoadConfig;

#pragma section(".rdata$loadcfg", read)
__declspec(allocate(".rdata$loadcfg")) const LoadConfig _load_config_used = {
    .size = sizeof(LoadConfig),
    .guard_cf_function_table = (unsigned long long)__guard_fids_table,
    .guard_cf_function_count = (unsigned long long)&__guard_fids_count,
    .guard_flags = (unsigned long long)&__guard_flags,
    .guard_long_jump_target_table = (unsigned long long)__guard_longjmp_table,
    .guard_long_jump_target_count = (unsigned long long)&__guard_longjmp_count
};

__declspec(noinline) int guard_alpha(int value) {
    return value + 3;
}

__declspec(noinline) int guard_beta(int value) {
    return value * 5;
}

__declspec(noinline) int guard_gamma(int value) {
    return value ^ 7;
}

volatile Probe guard_targets[] = {guard_alpha, guard_beta, guard_gamma};

int guard_entry(void) {
    return guard_targets[0](11);
}
