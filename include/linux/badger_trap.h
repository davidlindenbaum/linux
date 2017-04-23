#ifndef _LINUX_BADGER_TRAP_H
#define _LINUX_BADGER_TRAP_H

#define MAX_NAME_LEN	16
#define PTE_RESERVED_MASK	(_AT(pteval_t, 1) << 51)
#define CONSECUTIVE_FAKE_FAULT_LIMIT 100

extern char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN];

extern struct mutex badger_trap_mutex;
extern struct mutex checkpoint_mutex;

extern int checkpoint_use_split;

int is_badger_trap_process(const char* proc_name);
pte_t pte_unreserve(pte_t pte);
int is_pte_reserved(pte_t pte);
pmd_t pmd_unreserve(pmd_t pmd);
int is_pmd_reserved(pmd_t pmd);
void badger_trap_init(struct mm_struct *mm);

int transparent_fake_fault(struct mm_struct *mm, unsigned long address, pmd_t *page_table, unsigned int flags);
int do_fake_page_fault(struct mm_struct *mm, unsigned long address, pte_t *page_table, unsigned int flags, int huge);
void init_tlb_sim(struct mm_struct *mm, int keep_info);
void sim_tlb_flush(struct mm_struct *mm, unsigned long addr);
void sim_cow(struct mm_struct *mm, unsigned long addr);

int checkpoint_got_write(struct mm_struct *mm, unsigned long address, pmd_t *pmd, pte_t *pte, int thp);

struct checkpoint_data {
		long addr;
		int thp;
    uint8_t copied[64];
		union {
			pte_t *pte;
			pmd_t *pmd;
		};
		int already_copied;
		struct checkpoint_data *next;
};

struct sim_pte_info {
    long virt_addr;
    long phys_addr;
    int cow;
    uint8_t obv[64];
    uint8_t checkpoint_overlay[64];
		int split_by_checkpoint;
    struct sim_pte_info *next;
};

typedef struct tlb_entry {
    int present;
    int used;
    long address;
} tlb_entry_t;

typedef struct tlb_sim_data {
    int set_bits;
    int entries_per_set;
    tlb_entry_t **sets;
} tlb_sim_data_t;

typedef struct tlb_sim {
    struct mm_struct *mm;
    tlb_sim_data_t tlb_4k;
    tlb_sim_data_t tlb_2m;
    tlb_sim_data_t tlb_4k_overlay;
    tlb_sim_data_t tlb_2m_overlay;
    unsigned long total_dtlb_4k_misses;
    unsigned long total_dtlb_hugetlb_misses;
    unsigned long total_dtlb_4k_misses_overlay;
    unsigned long total_dtlb_hugetlb_misses_overlay;
    unsigned long total_dtlb_4k_misses_watched;
    unsigned long total_dtlb_hugetlb_misses_watched;
		int pages_copied;
		int pages_copied_no_split;
		struct checkpoint_data *checkpoint_data;
		struct checkpoint_data *checkpointed_data;
    int ignore_flush;
    struct sim_pte_info *huge_pte_info;
		struct task_struct *checkpoint_thread;
} tlb_sim_t;

void set_overlay(unsigned long addr, struct sim_pte_info *info, int checkpoint);
struct sim_pte_info *get_sim_pte(tlb_sim_t *sim, unsigned long addr);

extern int tlb_set_bits;
extern int tlb_entries_per_set;
extern int hugetlb_set_bits;
extern int hugetlb_entries_per_set;
extern int print_tlbsim_debug;


#endif /* _LINUX_BADGER_TRAP_H */
