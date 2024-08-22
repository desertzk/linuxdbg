#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include<linux/cdev.h>
#include<linux/fs.h>

#include <linux/device.h>
#include <linux/uaccess.h>

#include<linux/gfp.h>
#include<linux/mm.h>
#include<linux/slab.h>
#include <linux/highmem.h>
#include<linux/io.h>

#include"linuxdbgioctl.h"

//定义一个linuxdbg字符设备
static struct cdev lnxdbg_cdev;


dev_t led_dev_num;



static struct class  *lnxdbg_dev_class;
static struct device *lnxdbg_dev_device;


struct task_struct *g_task;
struct mm_struct *g_mm;


#define phys_to_pfn(p) ((p) >> PAGE_SHIFT)



static void print_vma(struct task_struct *task)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int count = 0;
    mm = task->mm;
    pr_info("\nThis mm struct has %d vmas.\n", mm->map_count);
    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        printk("\nVma number %d:\n", ++count);
	struct file *vmfile = vma ->vm_file;
	if(vmfile)
        	printk(" Starts at θx%lx,Ends at ox%lx flag %lx  file %s\n", vma->vm_start, vma->vm_end,vma->vm_flags ,vmfile->f_path.dentry->d_name.name);
	else
        	printk(" Starts at θx%lx,Ends at ox%lx flag %lx  file %s\n", vma->vm_start, vma->vm_end,vma->vm_flags ,"null");
    }

    pr_info("\nCode Segment start = 0x%lx,end = 0x%lx \n"
    "Data Segment start = 0x%lx,end = 0x%lx\n"
    "Stack Segment start ox%lx\n",mm->start_code, mm->end_code,mm->start_data, mm->end_data,mm->start_stack);

}


static void modify_page_content_value(struct page *page, unsigned long offset, int value) {
    void *vaddr;

    // Map the page to a virtual address
    vaddr = kmap(page);
    if (!vaddr) {
        pr_err("Failed to map page\n");
        return;
    }

    // Modify the value at the specified offset within the page
    *((int *)(vaddr + offset)) = value;

    // Unmap the page
    kunmap(page);
}


static int  page_content(unsigned long pfn)
{
    struct page *page;
    
    int i = 0;

    // Get the page structure for the given PFN
    page = pfn_to_page(pfn);

    // Read the content of the physical frame
    pr_info("Content of Physical Frame %lu:\n", pfn);
    unsigned char *data = page_address(page);
    printk("Page content in hex:\n");

    for (i = 0; i < PAGE_SIZE; ) {
        if (i % 16 == 0)
            printk("\n");

        printk("i %d   %02x %02x %02x %02x  %02x %02x %02x %02x",i, data[i++],data[i++],data[i++],data[i++]
		,data[i++],data[i++],data[i++],data[i++]);
    }

    printk("\n");


    return 0;
}


static int  get_phys_content(unsigned long phys_addr)
{
    struct page *page;
    
    //int i = 0;
    unsigned long pfn = phys_to_pfn(phys_addr);
    // Get the page structure for the given PFN
    page = pfn_to_page(pfn);

    // Read the content of the physical frame
    pr_info("Content of Physical Frame %lu:\n", pfn);

	unsigned long offset = (phys_addr & ~PAGE_MASK);

    unsigned char *data = page_address(page)+offset;
    printk("Page content in hex:\n");


    // printk("%02x %02x %02x %02x  %02x %02x %02x %02x", data[i++],data[i++],data[i++],data[i++]
    // ,data[i++],data[i++],data[i++],data[i++]);
    printk("%02x %02x %02x %02x  %02x %02x %02x %02x\n", 
           data[0], data[1], data[2], data[3], 
           data[4], data[5], data[6], data[7]);


    //printk("Page content in string %s\n",data);


    return 0;
}



// Function to convert user space virtual address to physical address
unsigned long virt_to_phys_pgt(unsigned long virt_addr) {
    pgd_t *pgd;
	p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page *page;
    unsigned long phys_addr = 0;

    // Get the current process's page global directory
    pgd = pgd_offset(current->mm, virt_addr);

    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        printk(KERN_ALERT "Error: PGD entry not found.\n");
        return 0;
    }

	p4d = p4d_offset(pgd, virt_addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;
    // Get the page upper directory
    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        printk(KERN_ALERT "Error: PUD entry not found.\n");
        return 0;
    }

    // Get the page middle directory
    pmd = pmd_offset(pud, virt_addr);

    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        printk(KERN_ALERT "Error: PMD entry not found.\n");
        return 0;
    }

    // Get the page table entry
    pte = pte_offset_map(pmd, virt_addr);

    if (!pte || pte_none(*pte)) {
        printk(KERN_ALERT "Error: PTE entry not found.\n");
        return 0;
    }

    // Get the physical address from the page table entry
    page = pte_page(*pte);
    phys_addr = page_to_phys(page) + (virt_addr & ~PAGE_MASK);
printk("Physical Address: 0x%lx",phys_addr);
    pte_unmap(pte);

    return phys_addr;
}



void print_page_tables(struct mm_struct *mm,unsigned long addr) {
    pgd_t *pgd;
	p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
//(pgd + pgd_index(address));
    pgd = pgd_offset(mm, addr);
	printk("(mm)->pgd 0x%x *pgd 0x%x pgd_index %x",pgd,*pgd,pgd_index(addr));
	/*
	if (!pgtable_l5_enabled())
		return (p4d_t *)pgd;
	return (p4d_t *)pgd_page_vaddr(*pgd) + p4d_index(address);
	*/
	p4d = p4d_offset(pgd, addr);
        unsigned long p4dpfn = p4d_val(*p4d) & p4d_pfn_mask(*p4d);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return;
    printk("p4d 0x%x *pgd 0x%x pgd_page_vaddr(*pgd) 0x%lx p4dpfn 0x%lx p4d_index %lx",p4d,*pgd,pgd_page_vaddr(*pgd),p4dpfn,p4d_index(addr));
	
	
	//p4d_pgtable(*p4d) + pud_index(address);
	pud = pud_offset(p4d, addr);
        unsigned long pudpfn = pud_val(*pud) & pud_pfn_mask(*pud);
	if (pud_none(*pud) || pud_bad(*pud))
		return;
    printk("pud 0x%x *p4d 0x%x p4d_pgtable(*p4d) 0x%lx pudpfn 0x%lx p4d_index %lx",pud,*p4d,p4d_pgtable(*p4d),pudpfn,pud_index(addr));

	//pud_pgtable(*pud) + pmd_index(address);
	pmd = pmd_offset(pud, addr);
        unsigned long pmdpfn = pmd_val(*pmd) & pmd_pfn_mask(*pmd);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return;
    printk("pmd 0x%x *pud 0x%x pud_pgtable(*pud) 0x%lx pmdpfn  0x%lx  pmd_index %lx",pmd,*pud,pud_pgtable(*pud),pmdpfn,pmd_index(addr));

//return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
	pte = pte_offset_map(pmd, addr);
	if (pte_none(*pte))
		return;
    printk("pte 0x%x *pmd 0x%x pmd_page_vaddr(*pmd) 0x%lx  pte_index %lx",pte,*pmd,pmd_page_vaddr(*pmd), pte_index(addr));

/*
	phys_addr_t pfn = pte_val(pte);
	pfn ^= protnone_mask(pfn);
	return (pfn & PTE_PFN_MASK) >> PAGE_SHIFT;
*/
	unsigned long pfn = pte_pfn(*pte);

	printk("Virtual Address: 0x%lx,pgd_val %lx p4d_val %lx pud_val %lx pmd_val %lx PTE Value: 0x%lx pfn 0x%lx\n"
	, addr,pgd_val(*pgd),p4d_val(*p4d),pud_val(*pud),pmd_val(*pmd), pte_val(*pte),pfn);


    unsigned long physical_address = ((pfn * PAGE_SIZE) | addr & (PAGE_SIZE - 1));
    get_phys_content(physical_address);


    printk("------------------page content begin--------------------");
	page_content(pfn);
    printk("------------------page content end--------------------");
	pte_unmap(pte);
    //}
}









static int lnxdbg_open(struct inode *inode, struct file *file)
{
	printk("lnxdbg open\n");
	return 0;
}

int lnxdbg_close(struct inode *inode, struct file *file)
{
	printk("lnxdbg_close\n");
	return 0;
}


// The read function
ssize_t lnxdbg_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    printk(KERN_INFO "Read operation called.\n");
    return 0;
}

// The write function
ssize_t lnxdbg_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{

	char virtual_address_str[64]={0};
	unsigned long long virtual_address=0;

	int err=copy_from_user(virtual_address_str,buf,count);
    if (err == 0) {
        printk(KERN_INFO "Write operation called.buf %s count %d\n",virtual_address_str,count);
    } else {
        printk(KERN_ERR "copy_from_user failed, %d bytes could not be copied\n", err);
    }

    /* Convert char* to unsigned long long 
    The second parameter specifies the base of the number in the string. 
    Passing 0 tells the function to automatically detect the base*/
    err = kstrtoull(virtual_address_str, 0, &virtual_address);
    if (err) {
        printk(KERN_ERR "Conversion failed\n");
        return err;
    }
    printk(KERN_INFO "virtual_address from user mode %llx \n",virtual_address);
print_page_tables(g_mm,virtual_address);

	
    return count;
}



int edit_user_data(struct mm_struct *mm,void __user *user_ptr, void *kernel_buffer, size_t size) {
    struct page *pages[1];    // Assuming the data fits within a single page.
    unsigned long user_address = (unsigned long)user_ptr;
    unsigned long offset;
    void *page_address;
    int ret;
    int locked = 1;
    
    // Pin the user page in memory
    ret = pin_user_pages_remote(mm,
			   user_address, 1,
			   FOLL_WRITE, pages,
			   NULL, &locked);
    if (ret <= 0) {
        pr_err("Failed to pin user pages %d\n",ret);
        return ret;
    }

     

    // Calculate offset within the page
    offset = user_address & (PAGE_SIZE - 1);

    // Map the page to kernel space
    page_address = kmap(pages[0]);

    // Copy data from user space to kernel buffer
    memcpy(page_address + offset, kernel_buffer, size);

    // Unmap the page
    kunmap(pages[0]);

    // Release the page
    put_page(pages[0]);

    return 0;
}



static long lnxdbg_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
 
    struct task_struct *target_task=NULL;
    pid_t pid;
    switch (cmd) {
        // case IOCTL_GET_MM:
        //     pid_t pid;
        //     if (copy_from_user(&pid, (pid_t __user *)arg, sizeof(pid_t))) {
        //         return -EFAULT;
        //     }

        //     // Find the task_struct corresponding to the given PID
        //     g_task = pid_task(find_vpid(pid), PIDTYPE_PID);
        //     if (!g_task) {
        //         printk(KERN_ERR "Cannot find task for PID %d\n", pid);
        //         return -ESRCH;
        //     }

        //     // Get the mm_struct
        //     g_mm = g_task->mm;

        //     // Print out the mm_struct address for demonstration
        //     if (g_mm) {
        //         printk(KERN_INFO "PID: %d, mm_struct: %p\n", pid, g_mm);
        //     } else {
        //         printk(KERN_INFO "PID: %d has no mm_struct (kernel thread or exited)\n", pid);
        //     }

        //     break;

        case IOCTL_PTE:
            struct pte_args pte;
            
            if (copy_from_user(&pte, arg, sizeof(struct pte_args))) {
                return -EFAULT;
            }
            pid = pte.pid;
            unsigned long virtual_address = pte.address;
            // Find the task_struct corresponding to the given PID
            target_task = pid_task(find_vpid(pid), PIDTYPE_PID);   
            if (!target_task) {
                printk(KERN_ERR "Cannot find task for PID %d\n", pid);
                return -ESRCH;
            }

            // Get the mm_struct
            struct mm_struct *target_mm = target_task->mm;

            // Print out the mm_struct address for demonstration
            if (target_mm) {
                printk(KERN_INFO "PID: %d, mm_struct: %p\n", pid, target_mm);
            } else {
                printk(KERN_INFO "PID: %d has no mm_struct (kernel thread or exited)\n", pid);
            }

            printk(KERN_INFO "virtual_address from user mode %llx \n",virtual_address);
            print_page_tables(target_mm,virtual_address);
            break;


        case IOCTL_PRINT_VMA:
            if (copy_from_user(&pid, (pid_t __user *)arg, sizeof(pid_t))) {
                return -EFAULT;
            }

            // Find the task_struct corresponding to the given PID
            target_task = pid_task(find_vpid(pid), PIDTYPE_PID);
            if (!target_task) {
                printk(KERN_ERR "Cannot find task for PID %d\n", pid);
                return -ESRCH;
            }
            // Print out the mm_struct address for demonstration
            printk(KERN_INFO "PID: %d\n", pid);
            print_vma(target_task);
            break;

        case IOCTL_EDIT_DATA:
        {
            struct ed_args ed;

            if (copy_from_user(&ed, arg, sizeof(struct ed_args))) {
                return -EFAULT;
            }
            //char value[64]={0};
            pid=ed.pid;
            unsigned long virtual_address = ed.address;
            // Find the task_struct corresponding to the given PID
            target_task = pid_task(find_vpid(pid), PIDTYPE_PID);
     
            // Print out the mm_struct address for demonstration
            printk(KERN_INFO "PID: %d address %x\n", pid,virtual_address);
            edit_user_data(target_task->mm,virtual_address,ed.value,sizeof(ed.value));

            break;

        }

        default:
            printk("unknow case\n");
            return -ENOTTY;
    }

    return 0;
}


static struct file_operations lnxdbg_fops={
	.owner = THIS_MODULE,
	.open = lnxdbg_open,
	.release = lnxdbg_close,
	.write = lnxdbg_write,
	.read = lnxdbg_read,
	.unlocked_ioctl = lnxdbg_ioctl,
};



static int __init linuxdbg_init(void)
{
	printk("Hello, World! from the kernel space...\n");
	int ret =0;

	//动态分配设备号 如果设备号有效则在/proc/devices文件中可以找到myled
	ret = alloc_chrdev_region(&led_dev_num,0,1,"linuxdbg");
	if(ret<0)
	{
		printk("register_chrdev_region error");
		goto err_register_chrdev_region;
	}
	printk("major %d minor %d\n",MAJOR(led_dev_num),MINOR(led_dev_num));



	//自动创建设备类，若创建成功，则在/sys/class目录下创建myled文件夹   
	lnxdbg_dev_class=class_create(THIS_MODULE,"linuxdbgclass");
	if(IS_ERR(lnxdbg_dev_class))
	{
		//将错误码指针转换为错误码
		ret = PTR_ERR(lnxdbg_dev_class);
		
		goto err_class_create;
		
	}
	
	//会在/sys/class/zkled目录下去创建linuxdbgdevice设备
	//会包含主设备号、次设备号、设备文件名
	//自动去/dev目录下创建linuxdbgdevice设备文件（设备节点）
	lnxdbg_dev_device = device_create(lnxdbg_dev_class,NULL,led_dev_num,NULL,"linuxdbgdevice");
	if (IS_ERR(lnxdbg_dev_device))
    {
		//将错误码指针转换为错误码
		ret = PTR_ERR(lnxdbg_dev_device);
		
		goto err_device_create;		
    }	


	cdev_init(&lnxdbg_cdev,&lnxdbg_fops);
	//将字符设备加入到内核
	ret = cdev_add(&lnxdbg_cdev,led_dev_num,1);
	if(ret<0)
	{
		printk("register_chrdev_region error");
		goto err_cdev_add;
	}






	return 0;




err_ioremap:
	//释放io内存
	release_mem_region(0xC001E000,0x24);

err_request_mem_region:
	device_destroy(lnxdbg_dev_class,led_dev_num);

err_device_create:	
	class_destroy(lnxdbg_dev_class);
	
err_class_create:
	cdev_del(&lnxdbg_cdev);	


err_cdev_add:
	unregister_chrdev_region(led_dev_num,1);
	
err_register_chrdev_region:
	return ret;
}

static void __exit linuxdbg_cleanup(void)
{
	printk("Good Bye, World! leaving kernel space...\n");

    device_destroy(lnxdbg_dev_class,led_dev_num);
    class_destroy(lnxdbg_dev_class);
	cdev_del(&lnxdbg_cdev);
	
	unregister_chrdev_region(led_dev_num,1);
	
}

module_init(linuxdbg_init);		// 注册模块
module_exit(linuxdbg_cleanup);	// 注销模块
MODULE_LICENSE("GPL"); 		//告诉内核该模块具有GNU公共许可证