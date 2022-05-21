#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/pm.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <linux/sysfs.h>

struct user_req {
    u32 pid;
    u32 key;
    u8 type;
    u8 irq_set;
    u8 is_mapped;
    struct file *filep;
    void *addr;
    void *mmap_addr;
    u64 length;
    u64 mmap_len;
    struct hlist_node node;
};

#define DEVNAME "cryptocard"
#define CC_DRIVER_NAME "cryptocard_mod"
#define CC_VENDOR_ID 0x1234
#define CC_DEVICE_ID 0xdeba
#define BAR0 0
#define BAR0_SIZE (1 << 20)
#define CONFIG_64BIT 1

#define CC_IOC_MAGIC   0x96
#define CC_IOCENC   _IOWR(CC_IOC_MAGIC, 0, struct user_req)
#define CC_IOCDEC   _IOWR(CC_IOC_MAGIC, 1, struct user_req)
#define CC_IOCSETDMA   _IO(CC_IOC_MAGIC, 2)
#define CC_IOCSETMMIO  _IO(CC_IOC_MAGIC, 3)
#define CC_IOCSETIRQ   _IO(CC_IOC_MAGIC, 4)
#define CC_IOCUNSETIRQ _IO(CC_IOC_MAGIC, 5)
#define CC_IOCSETKEYS  _IOW(CC_IOC_MAGIC, 6, u32)
#define CC_IOCMMAPLEN  _IOR(CC_IOC_MAGIC, 7, u64)

#define OFF_KEY 0x8
#define OFF_MMIO_SR 0x20 //MMIO status register
#define OFF_IRQ_ACK 0x64
#define OFF_IRQ_RAISE 0x60
#define OFF_MMIO_LEN 0x0c
#define OFF_MMIO_ADDR 0x80
#define OFF_ISR 0x24 //Offset of interrupt status register
#define OFF_DMA_ADDR 0x90
#define OFF_DMA_LEN 0x98
#define OFF_DMA_SR 0xa0

#define ISR_MMIO 0x001
#define ISR_DMA 0x100
#define DATA_OFFSET 0x1000
#define SIZE_HASH_TABLE 16
#define DMA_SIZE 1<<15
#define MAX_SIZE BAR0_SIZE - 0x1000

typedef enum {MMIO, DMA} type_t;
typedef enum {NIRQ, IRQ} irq_t;
typedef enum {ENC, DEC} operation_t;
typedef enum {ACTIVE, INACTIVE} status_t;

struct user_data {
    u8 is_mapped;
    void* addr;
    u64 length;
};

struct device_settings {
    u8 sett_type;
    u8 sett_irq_set;
    u32 sett_key;
};

struct driver_dev {
    u32 irq;
    dma_addr_t dma_addr;
    void* dma_buf;
    dev_t cc_devno;
    struct cdev cc_cdev;
    struct class *cc_class;
    struct task_struct *active_req;
    struct device_settings cc_sett;
    void *__iomem BAR0_vaddr;
    atomic_t device_opened;
    atomic_t mmap_lock;
    wait_queue_head_t wait_req;
    struct attribute_group cc_attr_group;
    struct hlist_head cc_req_map[SIZE_HASH_TABLE];
    struct pci_dev *dev;
};
