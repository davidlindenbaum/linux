#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/badger_trap.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/module.h>

int tlb_set_bits = 3;
int tlb_entries_per_set = 4;
int hugetlb_set_bits = 3;
int hugetlb_entries_per_set = 4;
char badger_trap_process[CONFIG_NR_CPUS][MAX_NAME_LEN] = {0};
int print_tlbsim_debug = 0;
unsigned long watched_addr = 0x7fff00000000;
int watched_len = 1024*1024*2;
DEFINE_MUTEX(badger_trap_mutex);


SYSCALL_DEFINE5(set_tlb_sim_params, int, set_bits, int, entries_per_set, int, huge_set_bits, int, huge_entries_per_set, int, print_verbose)
{
    tlb_set_bits = set_bits;
    tlb_entries_per_set = entries_per_set;
    hugetlb_set_bits = huge_set_bits;
    hugetlb_entries_per_set = huge_entries_per_set;
    print_tlbsim_debug = print_verbose;
    return 0;
}

/*
 * This syscall is generic way of setting up badger trap.
 * There are three options to start badger trap.
 * (1) 	option > 0: provide all process names with number of processes.
 * 	This will mark the process names for badger trap to start when any
 * 	process with names specified will start.
 *
 * (2) 	option == 0: starts badger trap for the process calling the syscall itself.
 *  	This requires binary to be updated for the workload to call badger trap. This
 *  	option is useful when you want to skip the warmup phase of the program. You can
 *  	introduce the syscall in the program to invoke badger trap after that phase.
 *
 * (3) 	option < 0: provide all pid with number of processes. This will start badger
 *  	trap for all pids provided immidiately.
 *
 *  Note: 	(1) will allow all the child processes to be marked for badger trap when
 *  		forked from a badger trap process.

 *		(2) and (3) will not mark the already spawned child processes for badger
 *		trap when you mark the parent process for badger trap on the fly. But (2) and (3)
 *		will mark all child spwaned from the parent process adter being marked for badger trap.
 */
SYSCALL_DEFINE3(init_badger_trap, const char __user**, process_name, unsigned long, num_procs, int, option)
{
  	unsigned int i;
  	char *temp;
  	unsigned long ret=0;
  	char proc[MAX_NAME_LEN];
  	struct task_struct * tsk;
  	unsigned long pid;
  	char *process_name_k[num_procs];
  	copy_from_user(process_name_k, process_name, num_procs * sizeof(*process_name));

  	if (option > 0) {
    		for (i=0; i<CONFIG_NR_CPUS; i++) {
    			  if (i<num_procs) {
    				    ret = strncpy_from_user(proc, process_name_k[i], MAX_NAME_LEN);
            } else {
    				    temp = strncpy(proc, "", MAX_NAME_LEN);
            }
    			  temp = strncpy(badger_trap_process[i], proc, MAX_NAME_LEN - 1);
    		}
  	}

  	// All other inputs ignored
  	if (option == 0) {
    		current->mm->badger_trap_en = 1;
    		badger_trap_init(current->mm);
  	}

  	if (option < 0) {
    		for (i=0; i<CONFIG_NR_CPUS; i++) {
      			if (i<num_procs) {
                ret = strncpy_from_user(proc, process_name_k[i], MAX_NAME_LEN);
        				ret = kstrtoul(proc, 10, &pid);
        				if (ret == 0) {
          					tsk = find_task_by_vpid(pid);
          					tsk->mm->badger_trap_en = 1;
          					badger_trap_init(tsk->mm);
        				}
      			}
    		}
  	}

  	return 0;
}

/*
 * This function checks whether a process name provided matches from the list
 * of process names stored to be marked for badger trap.
 */
int is_badger_trap_process(const char* proc_name)
{
  	unsigned int i;
  	for (i=0; i<CONFIG_NR_CPUS; i++) {
    		if(!strncmp(proc_name,badger_trap_process[i],MAX_NAME_LEN))
    			 return 1;
  	}
  	return 0;
}

/*
 * Helper functions to manipulate all the TLB entries for reservation.
 */
inline pte_t pte_mkreserve(pte_t pte)
{
    return pte_set_flags(pte, PTE_RESERVED_MASK);
}

inline pte_t pte_unreserve(pte_t pte)
{
    return pte_clear_flags(pte, PTE_RESERVED_MASK);
}

inline int is_pte_reserved(pte_t pte)
{
    if(native_pte_val(pte) & PTE_RESERVED_MASK)
        return 1;
    else
        return 0;
}

inline pmd_t pmd_mkreserve(pmd_t pmd)
{
    return pmd_set_flags(pmd, PTE_RESERVED_MASK);
}

inline pmd_t pmd_unreserve(pmd_t pmd)
{
    return pmd_clear_flags(pmd, PTE_RESERVED_MASK);
}

inline int is_pmd_reserved(pmd_t pmd)
{
    if(native_pmd_val(pmd) & PTE_RESERVED_MASK)
        return 1;
    else
        return 0;
}

void init_tlb_data(tlb_sim_data_t *data, int set_bits, int entries_per_set)
{
    int i;
    data->set_bits = set_bits;
    data->entries_per_set = entries_per_set;
    data->sets = kmalloc(sizeof(*data->sets) * 1 << set_bits, GFP_KERNEL);
    if (!data->sets) {
        if (print_tlbsim_debug) printk("kcalloc2 failed\n");
        return;
    }
    for (i = 0; i < 1 << tlb_set_bits; i++) {
        data->sets[i] = kcalloc(entries_per_set, sizeof(*data->sets[i]), GFP_KERNEL);
    }
}

void init_tlb_sim(struct mm_struct *mm, int keep_info)
{
    tlb_sim_t *s;
    if (!mm) {
        if (print_tlbsim_debug) printk("mm null\n");
        return;
    }
    s = kcalloc(1, sizeof(tlb_sim_t), GFP_KERNEL);
    if (!s) {
        if (print_tlbsim_debug) printk("kcalloc failed\n");
        return;
    }
    s->mm = mm;

    init_tlb_data(&s->tlb_4k, tlb_set_bits, tlb_entries_per_set);
    init_tlb_data(&s->tlb_2m, hugetlb_set_bits, hugetlb_entries_per_set);
    init_tlb_data(&s->tlb_4k_overlay, tlb_set_bits, tlb_entries_per_set);
    init_tlb_data(&s->tlb_2m_overlay, hugetlb_set_bits, hugetlb_entries_per_set);

    s->huge_pte_info = NULL;
    //if (keep_info) s->huge_pte_info = mm->tlb_sim->huge_pte_info;
    if (keep_info) {
        struct sim_pte_info *info = mm->tlb_sim->huge_pte_info;
        while (info) {
            struct sim_pte_info *info2 = kcalloc(1, sizeof(*info2), GFP_KERNEL);
            *info2 = *info;
            info2->next = s->huge_pte_info;
            s->huge_pte_info = info2;

            info = info->next;
        }
    }
    mm->tlb_sim = s;
}

/*
 * This function walks the page table of the process being marked for badger trap
 * This helps in finding all the PTEs that are to be marked as reserved. This is
 * espicially useful to start badger trap on the fly using (2) and (3). If we do not
 * call this function, when starting badger trap for any process, we may miss some TLB
 * misses from being tracked which may not be desierable.
 *
 * Note: This function takes care of transparent hugepages and hugepages in general.
 */
void badger_trap_init(struct mm_struct *mm)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t *page_table;
	spinlock_t *ptl;
	unsigned long address;
	unsigned long i,j,k,l;
	unsigned long user = 0;
	unsigned long mask = _PAGE_USER | _PAGE_PRESENT;
	struct vm_area_struct *vma = 0;
	pgd_t *base = mm->pgd;
  init_tlb_sim(mm, 0);
	for(i=0; i<PTRS_PER_PGD; i++)
	{
		pgd = base + i;
		if((pgd_flags(*pgd) & mask) != mask)
			continue;
		for(j=0; j<PTRS_PER_PUD; j++)
		{
			pud = (pud_t *)pgd_page_vaddr(*pgd) + j;
			if((pud_flags(*pud) & mask) != mask)
                        	continue;
			address = (i<<PGDIR_SHIFT) + (j<<PUD_SHIFT);
			if(vma && pud_huge(*pud) && is_vm_hugetlb_page(vma))
			{
				spin_lock(&mm->page_table_lock);
				page_table = huge_pte_offset(mm, address);
				*page_table = pte_mkreserve(*page_table);
				spin_unlock(&mm->page_table_lock);
				continue;
			}
			for(k=0; k<PTRS_PER_PMD; k++)
			{
				pmd = (pmd_t *)pud_page_vaddr(*pud) + k;
				if((pmd_flags(*pmd) & mask) != mask)
					continue;
				address = (i<<PGDIR_SHIFT) + (j<<PUD_SHIFT) + (k<<PMD_SHIFT);
				vma = find_vma(mm, address);
				if(vma && pmd_huge(*pmd) && (transparent_hugepage_enabled(vma)||is_vm_hugetlb_page(vma)))
				{
					spin_lock(&mm->page_table_lock);
					*pmd = pmd_mkreserve(*pmd);
					spin_unlock(&mm->page_table_lock);
					continue;
				}
				for(l=0; l<PTRS_PER_PTE; l++)
				{
					pte = (pte_t *)pmd_page_vaddr(*pmd) + l;
					if((pte_flags(*pte) & mask) != mask)
						continue;
					address = (i<<PGDIR_SHIFT) + (j<<PUD_SHIFT) + (k<<PMD_SHIFT) + (l<<PAGE_SHIFT);
					vma = find_vma(mm, address);
					if(vma)
					{
						page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
						*pte = pte_mkreserve(*pte);
						pte_unmap_unlock(page_table, ptl);
					}
					user++;
				}
			}
		}
	}
}

#define SHIFT_4K 12
#define SHIFT_2M 21
#define SET(a,n) (~(-1 << (n)) & (a))
#define TAG(a,n) ((a) >> (n))

void _sim_tlb_flush(tlb_sim_data_t *sim, unsigned long addr)
{
    int i, j;
    for (i = 0; i < 1 << sim->set_bits; i++) {
        if (sim->sets && sim->sets[i]) {
            for (j = 0; j < sim->entries_per_set; j++) {
                if (sim->sets[i][j].address == addr || addr == 0){
                    sim->sets[i][j].present = 0;
                }
            }
        }
    }
}

/*
 * If addr == 0 flush the whole simulated tlb, else flush that page
 */
void sim_tlb_flush(struct mm_struct *mm, unsigned long addr)
{
    tlb_sim_t *s;
    if (mm && mm->tlb_sim) {
        s = mm->tlb_sim;
        if (s->ignore_flush) return;
        _sim_tlb_flush(&s->tlb_4k, addr >> SHIFT_4K);
        _sim_tlb_flush(&s->tlb_2m, addr >> SHIFT_2M);
        _sim_tlb_flush(&s->tlb_4k_overlay, addr >> SHIFT_4K);
        _sim_tlb_flush(&s->tlb_2m_overlay, addr >> SHIFT_2M);
    }
}

int tlb_replace(unsigned long addr, tlb_sim_data_t *data, struct mm_struct *mm, int page_shift)
{
    unsigned long addr_trim = addr >> page_shift;
    tlb_entry_t *set = data->sets[SET(addr_trim, data->set_bits)];

    int i;
    int invalid_entry = -1, unused_entry = -1;
    unsigned long replace_addr;
    for (i = 0; i < data->entries_per_set; i++) {
        // If it's already in the tlb just set the used bit and return
        if (set[i].present && set[i].address == addr_trim) {
            set[i].used = 1;
            return 0;
        }
        // Keep track of the best replacement candidate
        if (!set[i].present) invalid_entry = i;
        else if (!set[i].used) unused_entry = i;
    }

    // Need to replace a valid entry
    if (invalid_entry < 0) {
        if (unused_entry >= 0) {
            replace_addr = set[unused_entry].address << page_shift;
            flush_tlb_mm_range(mm, replace_addr, replace_addr + (1 << page_shift), 0);
            invalid_entry = unused_entry;
        } else {
            // Everything's recently used, reset bits and evict last addr
            for (i = 0; i < data->entries_per_set; i++) set[i].used = 0;
            flush_tlb_mm(mm);
            replace_addr = set[data->entries_per_set - 1].address;
            invalid_entry = data->entries_per_set - 1;
        }
    }

    if (invalid_entry >= 0) {
        set[invalid_entry].present = 1;
        set[invalid_entry].used = 1;
        set[invalid_entry].address = addr_trim;
    }
    return 1;
}

struct sim_pte_info *get_pte(tlb_sim_t *sim, unsigned long addr)
{
    struct sim_pte_info *info = sim->huge_pte_info;
    while (info) {
        if (info->virt_addr == addr) return info;
        info = info->next;
    }
    return 0;
}

int is_in_overlay(unsigned long addr, uint8_t obv[64])
{
    unsigned int ind = (addr >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));
    return (obv[ind / 8] >> (ind % 8)) % 2;
}

void set_overlay(unsigned long addr, struct sim_pte_info *info)
{
    unsigned int ind = (addr >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));
    info->obv[ind / 8] |= (1 << (ind % 8));
}

void _tlb_miss(struct mm_struct *mm, unsigned long addr, int huge, int overlay)
{
    int miss;
    tlb_sim_t *sim = mm->tlb_sim;
    sim->ignore_flush = 1;
    miss = tlb_replace(addr, huge ? (overlay ? &sim->tlb_2m_overlay : &sim->tlb_2m) :
                      (overlay ? &sim->tlb_4k_overlay : &sim->tlb_4k), mm, huge ? SHIFT_2M : SHIFT_4K);
    sim->ignore_flush = 0;

    if (miss) {
        if (huge && overlay) sim->total_dtlb_hugetlb_misses_overlay++;
        else if (huge && !overlay) sim->total_dtlb_hugetlb_misses++;
        else if (!huge && overlay) sim->total_dtlb_4k_misses_overlay++;
        else sim->total_dtlb_4k_misses++;

        if (addr >= watched_addr && addr < watched_addr + watched_len) {
            if (huge && overlay) sim->total_dtlb_hugetlb_misses_watched++;
            else if (!huge && overlay) sim->total_dtlb_4k_misses_watched++;
        }
        if (print_tlbsim_debug > 2) printk("%s%s miss %lx\n", overlay ? "overlay: " : "non-overlay:", huge ? "2m" : "4k", addr);
    }
}

int should_reset(struct sim_pte_info *info) {
    int count = 0;
    int i, j;
    for (i = 0; i < sizeof(info->obv); i++) {
        for (j = 0; j < 8; j++) {
            if ((info->obv[i] >> j) % 2) count++;
        }
    }
    return count > 50;
}

void tlb_miss(struct mm_struct *mm, unsigned long addr, int huge, int write, unsigned long page_table)
{
    //2m aligned address of virtual page
    unsigned long addr2m = addr >> SHIFT_2M;
    //2m aligned address of physical page
    unsigned long phys2m = page_table >> SHIFT_2M;
    //index of virtual 4k page in 2m region
    unsigned long virt_ind = (addr >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));
    //index of physical 4k page in 2m region
    unsigned long phys_ind = (page_table >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));

    mutex_lock(&badger_trap_mutex);

    tlb_sim_t *sim = mm->tlb_sim;
    struct sim_pte_info *info = get_pte(sim, addr2m);

    struct test_list_node *tnode = sim->test_list;
    while(tnode) {
        if ((addr >> SHIFT_2M) == tnode->addr >> SHIFT_2M) tnode->touched = 1;
        tnode = tnode->next;
    }

    if (!huge && !info && virt_ind == phys_ind) {
        //we have a 4k page that's algined like a superpage - can create a new superpage here
        if (print_tlbsim_debug) printk("found aligned 4k page in %lx - creating superpage\n", addr2m << SHIFT_2M);
        if (print_tlbsim_debug) printk("adding new known page %lx\n", addr2m << SHIFT_2M);
        info = kcalloc(1, sizeof(*info), GFP_KERNEL);
        info->virt_addr = addr2m;
        info->phys_addr = phys2m;
        info->next = sim->huge_pte_info;
        sim->huge_pte_info = info;
    }

    if (info && !huge && virt_ind != phys_ind && !is_in_overlay(addr, info->obv)) {
      if (print_tlbsim_debug) printk("page %lx not in the correct index, setting overlay\n", (addr >> SHIFT_4K) << SHIFT_4K);
      set_overlay(addr, info);
    }

    if (info && info->phys_addr != phys2m) {
        if (huge && info->cow == 1) {
            //cow == 1 means it just got copied-on-write, which means the phys addr is about to change - now it has, so we set cow to 2
            info->cow = 2;
            info->phys_addr = phys2m;
        } else if (huge) {
            info->virt_addr = addr2m;
            info->phys_addr = phys2m;
            info->cow = 0;
            memset(info->obv, 0, sizeof info->obv);
            if (print_tlbsim_debug) printk("hugepage %lx has new physical address, resetting\n", addr2m << SHIFT_2M);
        } else if (!is_in_overlay(addr, info->obv)) {
            if (print_tlbsim_debug) printk("physical address for page %lx changed, setting overlay\n", addr2m << SHIFT_2M);
            set_overlay(addr, info);
        }
    }

    if (info && should_reset(info)) {
        if (print_tlbsim_debug) printk("page %lx has too many overlays, resetting\n", addr2m << SHIFT_2M);
        info->virt_addr = 0;
    }

    if (huge) _tlb_miss(mm, addr, 1, 0);
    else _tlb_miss(mm, addr, 0, 0);

    if (huge || info) {
        if (!info) {
            if (print_tlbsim_debug > 1) printk("adding new known page %lx\n", addr2m << SHIFT_2M);
            info = kcalloc(1, sizeof(*info), GFP_KERNEL);
            info->virt_addr = addr2m;
            info->phys_addr = phys2m;
            info->next = sim->huge_pte_info;
            sim->huge_pte_info = info;
        }

        /*if (info->cow) {
            //cow hugepage, flushing tlb so we get traps on writes
            sim->ignore_flush = 1;
            flush_tlb_mm_range(mm, addr2m << SHIFT_2M, (addr2m + 1) << SHIFT_2M, 0);
            sim->ignore_flush = 0;
        }*/

        //page is in known hugepage, going to 2m tlb (whether or not it's actually a 4k page)
        _tlb_miss(mm, addr, 1, 1);

        if (!huge && write && !is_in_overlay(addr, info->obv) && info->cow) {
            //do overlay-on-write
            if (print_tlbsim_debug) printk("got write to %lx in cow page, adding to overlay\n", addr);
            set_overlay(addr, info);
        }
        if (is_in_overlay(addr, info->obv)) {
            //overlay page, going to 4k tlb
            _tlb_miss(mm, addr, 0, 1);
        }
    } else {
        _tlb_miss(mm, addr, 0, 1);
    }
    mutex_unlock(&badger_trap_mutex);
}

void sim_cow(struct mm_struct *mm, unsigned long addr)
{
    unsigned long addr2m = addr >> SHIFT_2M;
    struct sim_pte_info *info = get_pte(mm->tlb_sim, addr2m);
    if (info) {
        if (print_tlbsim_debug) printk("cow on %lx, known page\n", addr);
        set_overlay(addr, info);
        info->cow = 1;
        mm->tlb_sim->ignore_flush = 1;
        flush_tlb_mm_range(mm, addr2m << SHIFT_2M, (addr2m + 1) << SHIFT_2M, 0);
        mm->tlb_sim->ignore_flush = 0;
    }
}

int transparent_fake_fault(struct mm_struct *mm, unsigned long address, pmd_t *page_table, unsigned int flags)
{
	unsigned long *touch_page_addr;
	unsigned long touched;
	unsigned long ret;
	static unsigned int consecutive = 0;
	static unsigned long prev_address = 0;

	if(address == prev_address)
		consecutive++;
	else
	{
		consecutive = 0;
		prev_address = address;
	}

  *page_table = pmd_unreserve(*page_table);
	if(consecutive > CONSECUTIVE_FAKE_FAULT_LIMIT)
	{
		printk("transparent hugepage consecutive fake fault on %lx\n", address);
		return 0;
	}

	/* Here where we do all our analysis */
	tlb_miss(mm, address, 1, flags & FAULT_FLAG_WRITE, pmd_val(*page_table));

	touch_page_addr = (void *)(address & PAGE_MASK);
	ret = copy_from_user(&touched, (__force const void __user *)touch_page_addr, sizeof(unsigned long));

	if(ret)
		return VM_FAULT_SIGBUS;

	*page_table = pmd_mkreserve(*page_table);
	return 0;
}

/*
 * This function handles the fake page fault introduced to perform TLB miss
 * studies. We can perform our work in this fuction on the page table entries.
 */
int do_fake_page_fault(struct mm_struct *mm, unsigned long address, pte_t *page_table, unsigned int flags, int huge)
{
	unsigned long *touch_page_addr;
	unsigned long touched;
	unsigned long ret;
	static unsigned int consecutive = 0;
	static unsigned long prev_address = 0;

	if(address == prev_address)
		consecutive++;
	else
	{
		consecutive = 0;
		prev_address = address;
	}

  *page_table = pte_unreserve(*page_table);
	if(consecutive > CONSECUTIVE_FAKE_FAULT_LIMIT)
	{
		printk("consecutive fake fault on %lx\n", address);
		return 0;
	}

	/* Here where we do all our analysis */
	tlb_miss(mm, address, huge, flags & FAULT_FLAG_WRITE, pte_val(*page_table));

	touch_page_addr = (void *)(address & PAGE_MASK);
	ret = copy_from_user(&touched, (__force const void __user *)touch_page_addr, sizeof(unsigned long));

	if(ret)
		return VM_FAULT_SIGBUS;

	*page_table = pte_mkreserve(*page_table);

	return 0;
}
