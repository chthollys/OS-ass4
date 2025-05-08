#ifndef IO_URING_MEMMAP_H
#define IO_URING_MEMMAP_H

#define IORING_MAP_OFF_PARAM_REGION		0x20000000ULL
#define IORING_MAP_OFF_ZCRX_REGION		0x30000000ULL

// Pins user-space buffer pages into memory and returns the corresponding page array
struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

#ifndef CONFIG_MMU
// Returns the mmap capabilities of the io_uring file when MMU is not configured
unsigned int io_uring_nommu_mmap_capabilities(struct file *file);
#endif
// Finds a suitable unmapped memory area for mapping io_uring structures
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags);
// Handles memory mapping operations for io_uring file
int io_uring_mmap(struct file *file, struct vm_area_struct *vma);

// Frees memory resources associated with an io_uring mapped region
void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);
// Creates a new memory region for io_uring operations with specified parameters
int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset);

// Creates a memory region for io_uring with additional safety checks for mmap operations
int io_create_region_mmap_safe(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset);

// Retrieves the pointer to the mapped memory region
static inline void *io_region_get_ptr(struct io_mapped_region *mr)
{
	return mr->ptr;
}

// Checks if a memory region is set by verifying if it has allocated pages
static inline bool io_region_is_set(struct io_mapped_region *mr)
{
	return !!mr->nr_pages;
}

#endif
