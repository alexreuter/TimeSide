/*
 * kernread
 *
 * emulates a kernel vulnerability that allows an attacker
 * to overwrite a kernel-mapped data pointer with an arbitrary
 * value. It was inspired by Nelson Elhage's NULL pointer
 * dereference module (NULLDEREF)
 *
 * Usage:
 * 	- compile and load the module
 * 	- mount debugfs (mount -t debugfs none /sys/kernel/debug/)
 *	- go to /sys/kernel/debug/kernread/ and have fun :)
 */

#include <linux/debugfs.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/delay.h>

/* buffer size for holding a virtual address */
#if	defined(__i386__)	/* x86 */
#define ADDR_SZ	16		/* 16 bytes */
#elif	defined(__x86_64__)	/* x86-64 */
#define ADDR_SZ	32		/* 32 bytes */
#endif

#define BUFSIZE 100

static char *output_arr;
struct debugfs_blob_wrapper *myblob;

struct datapoints{
	char datapoints[1000][40];
	int num_entries;
};

struct datapoints myData;

// const size_t mem_size = 1 << 20;
//first success

//const size_t mem_size = 1 << 20;
//const size_t mem_size = 536870912 * 2;
//const size_t mem_size = 1<<7;
//const size_t base_addr_inc = mem_size/2;
//const size_t base_addr_inc = mem_size/100;
//const size_t base_addr_inc = 1 << 18;
//2^31 is 2GB of bytes, which is the worst case scenario for a bank size
//Should definitelly change the probe size, assuming the memory is contiguous
//const size_t probe_inc = 1 << 8;
//const size_t probe_inc = mem_size/1000;

const size_t total_size = 1<<22;
const size_t window_size = total_size/8;
const size_t base_addr_inc = window_size;
const size_t probe_inc = window_size/100;

int entry = 0;
char* g_mem;
int base_addr_offset;

u8 buff_full;
u8 should_exit;
unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;

int inline measured_function(volatile int offset) {    
	volatile int w, x, y, z, a, b;
//	int i;	
//	for(i = 0; i < 100; i++){
	w = g_mem[base_addr_offset];
	x = g_mem[offset];
	asm volatile("clflush (%0)" : : "r" (g_mem + offset) : "memory");
   	asm volatile("clflush (%0)" : : "r" (g_mem + base_addr_offset) : "memory");
    	y = g_mem[base_addr_offset];
	z = g_mem[offset];
	asm volatile("clflush (%0)" : : "r" (g_mem + offset) : "memory");
    	asm volatile("clflush (%0)" : : "r" (g_mem + base_addr_offset) : "memory");
//	}
//    	a = g_mem[base_addr_offset];
//	b = g_mem[offset];
//	asm volatile("clflush (%0)" : : "r" (g_mem + offset) : "memory");
//	asm volatile("clflush (%0)" : : "r" (g_mem + base_addr_offset) : "memory");
//	return w + x + y + z + a + b;
	return 0;
} 

static int measure_timing(int offset) {    
    unsigned long flags; 
    uint64_t start, end;    
    //int variable = 0; 
    //unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;    
    //printk(KERN_INFO "Loading test module...\n");    

    preempt_disable(); /*we disable preemption on our CPU*/    
    raw_local_irq_save(flags); /*we disable hard interrupts on our CPU*/    /*at this stage we exclusively own the CPU*/    
    
   // printk(KERN_INFO "\n %p", (char *) g_mem + offset);

    //Invalidate both cache lines
    asm volatile("clflush (%0)" : : "r" (g_mem + offset) : "memory");
    asm volatile("clflush (%0)" : : "r" (g_mem + base_addr_offset) : "memory");

    asm   volatile ("CPUID\n\t"           
    				"RDTSC\n\t"           
    				"mov %%edx, %0\n\t"           
    				"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx"); 
    				/***********************************/ 
    				/*call the function to measure here*/ 
    				measured_function(offset);
    				/***********************************/ 
    asm   volatile("RDTSCP\n\t"          
    				"mov %%edx, %0\n\t"          
    				"mov %%eax, %1\n\t"    
    				"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");



    // Old bencmarking system
    // asm volatile (          
    //     "RDTSC\n\t"          
    //     "mov %%edx, %0\n\t"          
    //     "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low));   

    // measured_function(offset);   


    // asm volatile (          
    //     "RDTSC\n\t"          
    //     "mov %%edx, %0\n\t"          
    //     "mov %%eax, %1\n\t": "=r" (cycles_high1), "=r" (cycles_low1));  

    raw_local_irq_restore(flags); /*we enable hard interrupts on our CPU*/    
    preempt_enable();/*we enable preemption*/    
    start = ( ((uint64_t)cycles_high << 32) | cycles_low );    
    end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );

    //sprintf(myData.datapoints[entry], "%llu,p%p,v%p", (end - start), (void *) virt_to_phys((void *) g_mem + offset), (void *) (g_mem + offset));
    
    //Working before
    //sprintf(myData.datapoints[entry], "%llu,p%llu\n", (end - start),  virt_to_phys((void *) g_mem + offset));
    // entry++;
    //end

    //printk(KERN_INFO "  is %llu clock cycles, virt %p, phys %p", (end-start), (void *) g_mem + offset, (void *) virt_to_phys((void *) g_mem + offset));    
    return (int) (end - start);
}


static ssize_t
read_output(struct file*f, char __user *buf, size_t count, loff_t *off){
	int ret;
	// printk(KERN_INFO "Got a call to read_output!\n");
	ret = simple_read_from_buffer(buf, count, off, output_arr, 100);
	// printk(KERN_INFO "Finished copying to user buffer!\n");
	return ret;
}



/* handles to the files we will create */
static struct dentry *kernread_root	= NULL;
static struct dentry *output	= NULL;
static struct dentry *write_output		= NULL;
static struct dentry *dfs = NULL;

/* structs telling the kernel how to handle reads/writes to our files */
static const struct file_operations output_ops = {
	.read	= read_output,
};
//static const struct file_operations write_output_ops = {/
//	.write	= write_to_output,
//};


/* module cleanup; remove the files and the directory */
static void
cleanup_debugfs(void)
{
	/* cleanup */
	if (output != NULL)
		debugfs_remove(output);
	if (write_output != NULL)
		debugfs_remove(write_output);
	if (kernread_root != NULL){
		printk(KERN_INFO "Removed reutos!\n");
		debugfs_remove(kernread_root);
	}
	if (dfs != NULL)
		debugfs_remove(dfs);
}

/* module loading callback */
static int
kernread_init(void)
{
	const char str[40] = "this is fake";
	int i = 0;
	int j = 0;
	int y = 0;
	int sum = 0;
	int avg = 0;
	int min = 10000;
	// create the kernread directory in debugfs 
	kernread_root = debugfs_create_dir("reutos", NULL);
	//failed 
	if (kernread_root == NULL) {
		// verbose 
		printk(KERN_ERR "reutos: creating root dir failed\n");
		//return -ENODEV;
	}

	//Setup fake timing data struct
	for(i = 0; i < 1000; i++){
		for(j=0;j<13;j++){
			myData.datapoints[i][j] = str[j];
		}
	}

	printk(KERN_INFO "Done initializing myData\n");

	printk(KERN_INFO "Getting memory for myblob struct");
	myblob = (struct debugfs_blob_wrapper *) kmalloc(sizeof(struct debugfs_blob_wrapper), GFP_KERNEL);
	if(myblob == NULL){
		printk(KERN_INFO "Couldnt allocate memory for myblob\n");
		return -ENOMEM;
	}

	myData.num_entries = 1000;
	myblob->data = (void *) &myData;
	myblob->size = 1000 * 40;

	printk(KERN_INFO "Done setting up blob\n");

	dfs = debugfs_create_blob("mydata", 0777, kernread_root, myblob);

	if (dfs == NULL){
		printk(KERN_INFO "Couldnt create blob\n");
	}

	printk(KERN_INFO "Created mydata blob in debugfs\n");

	debugfs_create_u8("buff_full", 0777, kernread_root, &buff_full);
	debugfs_create_u8("exit_module", 0777, kernread_root, &should_exit);

	// Allocate the buffer for the data
	output_arr = (char *) kmalloc(BUFSIZE, GFP_KERNEL | GFP_ATOMIC);
	if(output_arr == NULL){
		printk(KERN_ERR "reutos: unable to kmalloc data array");
		goto out_err;
	}

	// Zero it out
	memset(output_arr, 0, BUFSIZE);

	// debugfd_create_file(name, mode, parent, data, fops)

	/* create the files with the appropriate `fops' struct and perms */
	/*
	output	= debugfs_create_file("output",
						//0222, //read, read, read
						0444,
						kernread_root,
NULL,
						&output_ops);
*/
	// write_output	= debugfs_create_file("write_output",
	// 					//0444, //write, write, write
	// 					0222,
	// 					kernread_root,
	// 					NULL,
	// 					&write_output_ops);

	/* error handling */
//	if (output == NULL)
//		goto out_err;

	i = 0;
	printk(KERN_INFO "Starting rowhammering!\n");
	g_mem = (char *) kmalloc(total_size, GFP_KERNEL | GFP_ATOMIC);
	printk(KERN_INFO "\n g_mem start = %p, %d\n", g_mem, (int) g_mem);
	base_addr_offset = 0;

	if(g_mem == NULL){
		goto out_err;
	}

	 //PREAMBLE
    // This seemed to be the same as the instrcutions that we surround the hot function with
    asm   volatile ("CPUID\n\t"           
    				"RDTSC\n\t"           
    				"mov %%edx, %0\n\t"           
    				"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx"); 
    asm   volatile("RDTSCP\n\t"          
    				"mov %%edx, %0\n\t"          
    				"mov %%eax, %1\n\t"          
    				"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx"); 
    asm   volatile ("CPUID\n\t"           
    				"RDTSC\n\t"           
    				"mov %%edx, %0\n\t"           
    				"mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low):: "%rax", "%rbx", "%rcx", "%rdx"); 
    asm   volatile("RDTSCP\n\t"          
    				"mov %%edx, %0\n\t"          
    				"mov %%eax, %1\n\t"          
    				"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");

	j = 0;
	for(j = 0; j <= total_size - window_size; j += base_addr_inc){
		//Record the base address
        	sprintf(myData.datapoints[entry], "start: %lld \n", virt_to_phys((void *) g_mem + base_addr_offset));
		printk(KERN_INFO "dpts[entry] = %s, entry is %d\n", myData.datapoints[entry], entry);
		entry++;

		for(i = 0; i <= window_size - probe_inc; i += probe_inc){
			//if(i%(window_size/100) == 0){
			//	printk(KERN_INFO "%ld percent\n", i/(mem_size/100));
			//}
			if(entry >= 1000){
				// The buffer is full
				buff_full = 1;
			wait:
				//printk(KERN_INFO "The buffer is full, waiting...\n");
				//printk(KERN_INFO "First string: %s\n", myData.datapoints[0]);
				msleep(100);
				//printk(KERN_INFO "Should exit: %d\n", should_exit);
				if(should_exit == 1){
					break;
				}else if(buff_full){
					goto wait;
				}else{
					//printk(KERN_INFO "Yay the user read the buffer, clearing it and continuing...\n");
					// The user read all of the kernel data
					// Zero out the buffer, and set entry to 0
					memset(myblob->data, 0, sizeof(struct datapoints));
					// memset(myblob, 0, sizeof(struct datapoints));
					entry = 0;
				}
			}
			
			
			for(y = 0; y < 5000; y++){
				sum = measure_timing(i);
				if(sum < min){
					min = sum;
				}
			}

			// avg = sum / 1000;
			sprintf(myData.datapoints[entry], "%d,p%llu\n", min,  virt_to_phys((void *) g_mem + base_addr_offset + i));
    			entry++;
		}
		printk(KERN_INFO "Finished memory space for %p\n", (void *) virt_to_phys((char *) g_mem + base_addr_offset));
		base_addr_offset += base_addr_inc;
	}

	printk(KERN_INFO "Gone through the entire memory space");
	//Want to wait until the user read the last piece of data
	buff_full = 1;
	endwait:
	if(buff_full){
		printk(KERN_INFO "Waiting for user to read data at end");
		msleep(100);
		goto endwait;
	}


	cleanup_debugfs();

	/* return with success */
	return 0;

out_err:	/* cleanup */
	printk(KERN_ERR "reutos: creating files in root dir failed\n");
	cleanup_debugfs();

	/* return with failure */
	return -ENODEV;
}

/* module unloading callback */
static void
kernread_exit(void)
{
	cleanup_debugfs();
}


/* register module load/unload callbacks */
module_init(kernread_init);
module_exit(kernread_exit);

/* (un)necessary crap */
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alex Reuter");
MODULE_DESCRIPTION("A very simple proof of concept for kernel to user communication via debgufs");
MODULE_VERSION("2.71alpha");
