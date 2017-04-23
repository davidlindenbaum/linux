#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/badger_trap.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/kthread.h>

DEFINE_MUTEX(checkpoint_mutex);
void init_mem_checkpoint(struct mm_struct *mm);
static int checkpoint_thread(void *mm_ptr);

char page_mem[4096];
int checkpoint_rate = 10;
long nsec_per_page_write = 5000;
int checkpoint_use_split = 0;

SYSCALL_DEFINE3(set_checkpoint_params, int, rate, int, use_split, long, write_time)
{
    checkpoint_rate = rate;
    checkpoint_use_split = use_split;
    nsec_per_page_write = write_time;
    return 0;
}

SYSCALL_DEFINE3(mem_checkpoint_test, const char __user**, process_name, unsigned long, num_procs, int, option)
{
  unsigned int i;
  unsigned long ret=0;
  char proc[MAX_NAME_LEN];
  struct task_struct * tsk;
  unsigned long pid;
  char *process_name_k[num_procs];
  copy_from_user(process_name_k, process_name, num_procs * sizeof(*process_name));

  // All other inputs ignored
  if (option == 0) {
    if (!current->mm->badger_trap_en) {
      current->mm->badger_trap_en = 1;
      badger_trap_init(current->mm);
    }
    init_mem_checkpoint(current->mm);
  } else {
    for (i=0; i<CONFIG_NR_CPUS; i++) {
      if (i<num_procs) {
        ret = strncpy_from_user(proc, process_name_k[i], MAX_NAME_LEN);
        ret = kstrtoul(proc, 10, &pid);
        if (ret == 0) {
          tsk = find_task_by_vpid(pid);
          if (!tsk->mm->badger_trap_en) {
            tsk->mm->badger_trap_en = 1;
            badger_trap_init(tsk->mm);
          }
          init_mem_checkpoint(tsk->mm);
        }
      }
    }
  }
  return 0;
}

void init_mem_checkpoint(struct mm_struct *mm) {
  mm->tlb_sim->checkpoint_thread = kthread_run(checkpoint_thread, mm, "checkpoint");
}

void do_mem_checkpoint(struct mm_struct *mm) {
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t *page_table;
	spinlock_t *ptl;
	unsigned long address;
	unsigned long i,j,k,l;
	unsigned long user = 0;
	unsigned long mask = _PAGE_USER | _PAGE_PRESENT | _PAGE_RW;
	struct vm_area_struct *vma = 0;
	pgd_t *base = mm->pgd;
  int count = 0;

  printk("Start checkpoint\n");
  mutex_lock(&checkpoint_mutex);
  spin_lock(&mm->page_table_lock);
  
  struct checkpoint_data *data;
  data = mm->tlb_sim->checkpointed_data;
  while(data) {
    kfree(data);
    data = data->next;
  }
  mm->tlb_sim->checkpointed_data = NULL;
  
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
        printk("regular hugepage found, not checkpointing %lx\n", address);
				/*page_table = huge_pte_offset(mm, address);
        struct checkpoint_data *data = kcalloc(1, sizeof(*data), GFP_KERNEL);
        data->addr = address;
        data->pte = page_table;
        data->size = PAGE_SIZE * 512;
        data->next = mm->tlb_sim->checkpoint_data;
        mm->tlb_sim->checkpoint_data = data;
  			//spin_lock(&mm->page_table_lock);
        *page_table = pte_wrprotect(*page_table);
        flush_tlb_page(vma, address);
				//spin_unlock(&mm->page_table_lock);
        count++;*/
				continue;
			}
			for(k=0; k<PTRS_PER_PMD; k++)
			{
				pmd = (pmd_t *)pud_page_vaddr(*pud) + k;
				if((pmd_flags(*pmd) & mask) != mask)
					continue;
				address = (i<<PGDIR_SHIFT) + (j<<PUD_SHIFT) + (k<<PMD_SHIFT);
				vma = find_vma(mm, address);

        struct sim_pte_info *info = get_sim_pte(mm->tlb_sim, address >> 21);
        int fake_thp = (info && info->split_by_checkpoint);

				if(vma && pmd_huge(*pmd) && (transparent_hugepage_enabled(vma)||is_vm_hugetlb_page(vma)))
				{
          if (print_tlbsim_debug > 2) printk("Write protecting thp %lx\n", address);
          struct checkpoint_data *data = kcalloc(1, sizeof(*data), GFP_KERNEL);
          data->addr = address;
          data->pmd = pmd;
          data->thp = 1;
          data->next = mm->tlb_sim->checkpoint_data;
          mm->tlb_sim->checkpoint_data = data;
  				//spin_lock(&mm->page_table_lock);
          *pmd = pmd_wrprotect(*pmd);
          flush_tlb_page(vma, address);
					//spin_unlock(&mm->page_table_lock);
          count++;
					continue;
				} else if (fake_thp) {
          if (print_tlbsim_debug > 2) printk("Write protecting fake thp %lx\n", address);
          struct checkpoint_data *data = kcalloc(1, sizeof(*data), GFP_KERNEL);
          data->addr = address;
          data->pmd = pmd;
          data->thp = 1;
          data->next = mm->tlb_sim->checkpoint_data;
          mm->tlb_sim->checkpoint_data = data;
          count++;
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
            if (print_tlbsim_debug > 2) printk("Write protecting 4k %lx\n", address);
            if (!fake_thp) {
              struct checkpoint_data *data = kcalloc(1, sizeof(*data), GFP_KERNEL);
              data->addr = address;
              data->pte = pte;
              data->next = mm->tlb_sim->checkpoint_data;
              mm->tlb_sim->checkpoint_data = data;
              count++;
            }
  					page_table = pte_offset_map_lock(mm, pmd, address, &ptl);
            *pte = pte_wrprotect(*pte);
            flush_tlb_page(vma, address);
						pte_unmap_unlock(page_table, ptl);
					}
					user++;
				}
			}
		}
	}
  spin_unlock(&mm->page_table_lock);
  printk("Write protected %d pages\n", count);
  mutex_unlock(&checkpoint_mutex);
}

static int checkpoint_thread(void *mm_ptr) {
  //int pages_copied_overlay = 0;
  struct mm_struct *mm = (struct mm_struct*)mm_ptr;
  struct checkpoint_data *data;
  struct checkpoint_data data_val;
  struct timespec time;
  getnstimeofday(&time);
  time_t next = time.tv_sec + checkpoint_rate;
	while (!kthread_should_stop()) {
    getnstimeofday(&time);
    if (time.tv_sec >= next) {
      printk("do checkpoint\n");
      do_mem_checkpoint(mm);
      data = mm->tlb_sim->checkpoint_data;
      while(data) {
        mutex_lock(&checkpoint_mutex);

        data_val = *data;
  			if (print_tlbsim_debug > 1) printk("checkpointing page %lx\n", data_val.addr);

        long copy_end = time.tv_nsec + (nsec_per_page_write * (data_val.thp ? 512 : 1));
        mutex_unlock(&checkpoint_mutex);
        while(time.tv_nsec < copy_end) {
          getnstimeofday(&time);
        }
        mutex_lock(&checkpoint_mutex);

        if (print_tlbsim_debug > 1) printk("done checkpointing page %lx\n", data_val.addr);
      	spin_lock(&mm->page_table_lock);
        if (data_val.thp) {
          unsigned long addr;
          pte_t *page_table;
          for (addr = data_val.addr; addr < (data_val.addr + (1 << 21)); addr += 4096) {
            page_table = pte_offset_map(data_val.pmd, addr);
            *page_table = pte_mkwrite(*page_table);
            flush_tlb_page(find_vma(mm, addr), addr);
          }
        } else {
          *data_val.pte = pte_mkwrite(*data_val.pte);
          flush_tlb_page(find_vma(mm, data_val.addr), data_val.addr);
        }
      	spin_unlock(&mm->page_table_lock);
        
        mm->tlb_sim->checkpoint_data = data->next;
        data->next = mm->tlb_sim->checkpointed_data;
        mm->tlb_sim->checkpointed_data = data;

        //kfree(data);
        data = mm->tlb_sim->checkpoint_data;
        mutex_unlock(&checkpoint_mutex);
      }

      /*mutex_lock(&badger_trap_mutex);
      struct sim_pte_info *info = mm->tlb_sim->huge_pte_info;
      while (info) {
        if (info->virt_addr) {
          int cp_overlays = 0, not_cp_overlays = 0, i;
          for (i = 0; i < 512; i++) {
            if (!((info->obv[ind / 8] >> (ind % 8)) % 2)) {
              if ((info->checkpoint_overlay[ind / 8] >> (ind % 8)) % 2) cp_overlays++;
              else not_cp_overlays++;
            }
          }
          if (cp_overlays < not_cp_overlays) pages_copied_overlay += cp_overlays;
          else pages_copied_overlay += not_cp_overlays;
        }
        info = info->next;
      }
      mutex_unlock(&badger_trap_mutex);*/
      
			printk("Checkpoint done\n");
			printk("pages cow'd split: %d\n",mm->tlb_sim->pages_copied);
			printk("pages cow'd no split: %d\n",mm->tlb_sim->pages_copied_no_split);
			//printk("additional copies for overlay: %d\n",pages_copied_overlay);
      mm->tlb_sim->pages_copied = 0;
      mm->tlb_sim->pages_copied_no_split = 0;
      //pages_copied_overlay = 0;
      next += checkpoint_rate;
    }
  }
  return 0;
}

#define SHIFT_4K 12
#define SHIFT_2M 21
void set_copied(unsigned long addr, struct checkpoint_data *data)
{
  unsigned int ind = (addr >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));
  data->copied[ind / 8] |= (1 << (ind % 8));
}
int is_copied(unsigned long addr, uint8_t arr[64])
{
  unsigned int ind = (addr >> SHIFT_4K) % (1 << (SHIFT_2M - SHIFT_4K));
  return (arr[ind / 8] >> (ind % 8)) % 2;
}

int checkpoint_got_write(struct mm_struct *mm, unsigned long address, pmd_t *pmd, pte_t *pte, int thp) {
  struct checkpoint_data *data = mm->tlb_sim->checkpoint_data;
  struct sim_pte_info *info;
  int cnt = 0;
  int cnt2 = 0;
  pte_t *page_table;
  unsigned long addr;
  unsigned long mask = thp ? HPAGE_PMD_MASK : PAGE_MASK;
  
  while(data) {
    if (data->addr == (address & (data->thp ? HPAGE_PMD_MASK : PAGE_MASK))) {
      if (thp && !data->thp) {
        printk("Error: got thp fault but 4k data %lx\n", (address & mask));
        continue;
      }
      if ((data->thp && is_copied(address, data->copied)) || (!data->thp && data->already_copied)) {
        printk("%lx already copied, thp:%d\n", address & PAGE_MASK, thp);
        continue;
      }
      if (print_tlbsim_debug > 1) printk("copy on write %s\n", thp ? "thp" : "4k");
      if (!checkpoint_use_split && thp) {
        for (addr = address & mask; addr < ((address & mask) + (1 << 21)); addr += 4096) {
          __copy_from_user_inatomic(page_mem, (void*)addr, PAGE_SIZE);
        }
      } else {
        __copy_from_user_inatomic(page_mem, (void*)(address & PAGE_MASK), PAGE_SIZE);
      }

      info = get_sim_pte(mm->tlb_sim, address >> SHIFT_2M);
      if (info) {
        set_overlay(address, info, 1);
        if (thp) info->split_by_checkpoint = 1;
      } else if (thp) {
        printk("missing sim pte info for %lx\n", address & mask);
      }
      mm->tlb_sim->pages_copied++;
      if ((data->thp || (info && info->split_by_checkpoint)) && !data->already_copied) mm->tlb_sim->pages_copied_no_split += 512;
      else if (!data->already_copied) mm->tlb_sim->pages_copied_no_split++;

      if (data->thp) set_copied(address, data);
      data->already_copied = 1;

      split_huge_pmd(find_vma(mm, address), pmd, address);
      page_table = pte_offset_map(pmd, address);
      *page_table = pte_mkwrite(*page_table);
      flush_tlb_page(find_vma(mm, address), address);
      return 1;
    }
    data = data->next;
    cnt++;
  }
  data = mm->tlb_sim->checkpointed_data;
  while(data) {
    if (data->addr == (address & mask)) {
      printk("%s got already checkpointed page %lx\n", thp ? "thp" : "4k", (address & HPAGE_PMD_MASK));
      split_huge_pmd(find_vma(mm, address), pmd, address);
      page_table = pte_offset_map(pmd, address);
      *page_table = pte_mkwrite(*page_table);
      flush_tlb_page(find_vma(mm, address), address);
      return 1;
    }
    data = data->next;
    cnt2++;
  }
  if (print_tlbsim_debug > 1 && cnt > 0) printk("%d, %d searched, no match for %lx\n", cnt, cnt2, address & mask);
  return 0;
}

/*int checkpoint_got_write(struct mm_struct *mm, unsigned long address, pte_t *pte, int huge) {
  struct checkpoint_data *data = mm->tlb_sim->checkpoint_data;
  struct checkpoint_data *prev = NULL;
  struct sim_pte_info *info;
  int cnt = 0;

  while(data) {
    if (data->addr == (address & (huge ? HPAGE_PMD_MASK : PAGE_MASK))) {
      
      if (data->already_copied) {
        printk("%lx already copied\n", data->addr);
        *pte = pte_mkwrite(*pte);
        continue;
      }
      if (print_tlbsim_debug > 1 && huge) printk("copy on write huge\n");
      else if (print_tlbsim_debug > 2) printk("copy on write 4k\n");
      mm->tlb_sim->pages_copied += huge ? 512 : 1;
      if (huge) mm->tlb_sim->pages_copied_no_split += 512;
      else if (!data->was_huge) mm->tlb_sim->pages_copied_no_split++;
      __copy_from_user_inatomic(page_mem, (void*)(address & PAGE_MASK), PAGE_SIZE);

      info = get_sim_pte(mm->tlb_sim, address >> 21);
      if (info) {
        set_overlay(address, info);
      } else if (huge) {
        printk("missing sim pte info for %lx\n", address);
      }
      *pte = pte_mkwrite(*pte);
      flush_tlb_page(find_vma(mm, address), address);
      data->already_copied = 1;
      return 1;
    }
    prev = data;
    data = data->next;
    cnt++;
  }
  data = mm->tlb_sim->checkpointed_data;
  prev = NULL;
  while(data) {
    if (data->addr == (address & (huge ? HPAGE_PMD_MASK : PAGE_MASK))) {
      printk("b got already checkpointed page %lx\n", (address & (huge ? HPAGE_PMD_MASK : PAGE_MASK)));
      if (prev) prev->next = data->next;
      else mm->tlb_sim->checkpointed_data = data->next;
      kfree(data);

      *pte = pte_mkwrite(*pte);
      flush_tlb_page(find_vma(mm, address), address);
      return 1;
    }
    prev = data;
    data = data->next;
  }
  if (print_tlbsim_debug > 1 && cnt > 0) printk("%d searched, no match\n", cnt);
  return 0;
}*/