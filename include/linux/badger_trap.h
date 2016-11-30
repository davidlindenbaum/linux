#ifndef _LINUX_BADGER_TRAP_H
#define _LINUX_BADGER_TRAP_H

#define MAX_NAME_LEN	16
#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)

extern char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN];

int is_badger_trap_process(const char* proc_name);
pte_t pte_mkreserve(pte_t pte);
pte_t pte_unreserve(pte_t pte);
int is_pte_reserved(pte_t pte);
pmd_t pmd_mkreserve(pmd_t pmd);
pmd_t pmd_unreserve(pmd_t pmd);
int is_pmd_reserved(pmd_t pmd);
void badger_trap_init(struct mm_struct *mm);


struct sim_pte_info {
    long virt_addr;
    long phys_addr;
    int cow;
    uint8_t obv[64];
    struct sim_pte_info *next;
};

typedef struct tlb_entry {
    int present;
    int used;
    long address;
} tlb_entry_t;

typedef struct tlb_sim {
    struct mm_struct *mm;
    int set_bits;
    int entries_per_set;
    int huge_set_bits;
    int huge_entries_per_set;
    tlb_entry_t **sets;
    tlb_entry_t **hugesets;
    unsigned long total_dtlb_4k_misses;
    unsigned long total_dtlb_misses;
    unsigned long total_dtlb_hugetlb_misses;
    int ignore_flush;
    struct sim_pte_info *huge_pte_info;
} tlb_sim_t;

void init_tlb_sim(struct mm_struct *mm, int keep_info);
void tlb_miss(struct mm_struct *mm, unsigned long addr, int huge, int write);
void sim_tlb_flush(struct mm_struct *mm, unsigned long addr);
void sim_cow(struct mm_struct *mm, unsigned long addr);

extern int tlb_set_bits;
extern int tlb_entries_per_set;
extern int hugetlb_set_bits;
extern int hugetlb_entries_per_set;


#endif /* _LINUX_BADGER_TRAP_H */
