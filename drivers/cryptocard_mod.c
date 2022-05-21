#include "cryptocard_mod.h"

static struct pci_device_id module_ids[] = {
    { PCI_DEVICE(CC_VENDOR_ID, CC_DEVICE_ID) },
    {}
};
MODULE_DEVICE_TABLE(pci, module_ids);

int err;
static struct driver_dev *cc_data;
DEFINE_MUTEX(device_mutex);

/*Return the user_req object with these attribute values*/
struct user_req* get_user_req(struct file *filep) {
    int i, flag = 0;
    struct user_req *req = NULL;
    hash_for_each(cc_data->cc_req_map, i, req, node) {
        if (req->pid == current->pid && req->filep == filep) {
            flag = 1;
            break;
        }
    }
    if (flag)
        return req;
    return NULL;
}

/*This function does the following:
* - Check if the config is set properly
* - Check validity of user buffer and length
*/
int check_request(struct user_req *req, struct user_data *data) {
    u8 type = req->type;
    u8 irq_set = req->irq_set;
    if (type != MMIO && type != DMA)
        return -EPERM; 
    if(irq_set != IRQ && irq_set != NIRQ)
        return -EPERM;
    if (req->is_mapped != data->is_mapped)
        return -EPERM;
    if (data->is_mapped) {
        if (!access_ok(data->addr, data->length))
            return -EPERM;
        if (!( data->addr >= req->mmap_addr && (data->addr+data->length) <= (req->mmap_addr+req->mmap_len) ))
            return -EPERM;
    }
    
    return 0;
}

/*If busy return 1 else 0*/ 
static int check_device_busy(void) {
    void *__iomem vaddr = cc_data->BAR0_vaddr;
    u8 mmio_sr;
    mmio_sr = ioread8(vaddr + OFF_MMIO_SR);
    if (mmio_sr & 0x1) return 1;
    return 0;
}

/*Check if DMA operations is complete or not
* If complete return 0 else 1*/
static int check_dma_busy(void) {
    void *__iomem vaddr = cc_data->BAR0_vaddr;
    u8 dma_sr;
    dma_sr = ioread8(vaddr + OFF_DMA_SR);
    if (dma_sr & 0x1) return 1;
    return 0;
}

/*Sets config on the device*/
u64 set_config(u8 type, u8 irq, u8 op, u32 key) {
    u64 dma_cr;
    u32 mmio_sr;
    if (type == MMIO) {
        dma_cr = 0;
        mmio_sr = (op << 1) | (irq << 7);
        iowrite32(mmio_sr, cc_data->BAR0_vaddr + OFF_MMIO_SR);
    }
    else if (type == DMA) {
        dma_cr = 1 | (op << 1) | (irq << 2);
    }
    iowrite32(key, cc_data->BAR0_vaddr + OFF_KEY);
    pr_info("CryptoCard: config type = %d irq = %d op = %d key = %u\n", type, irq, op, key);

    cc_data->cc_sett.sett_type = type;
    cc_data->cc_sett.sett_irq_set = irq;
    cc_data->cc_sett.sett_key = key;
    
    return dma_cr;
}

/*MMIO without interrupt*/
static int init_default_driver(void) {
    pr_info("CC: Setting deault config...\n");
    set_config(0,0,0,0);
    return 0;
}

/*Copies required data from user*/
int prepare_data(struct user_req *req) {
    pr_info("CC: Preparing the data req = %p, pid = %u\n", req, current->pid);
    if (!req->is_mapped) {
        if (req->type == MMIO) {
            if (copy_from_user(cc_data->BAR0_vaddr + DATA_OFFSET, req->addr, req->length) == 0) {
                return req->length;
            }
        } else {
            if (copy_from_user(cc_data->dma_buf, req->addr, req->length) == 0) {
                return req->length;
            }
        }
    }
    return 0;
}

/*Copies data back to user buffer*/
int complete_req(struct user_req *req) {
    pr_info("CC: Request completed. Copying result back to user. req = %p, pid = %u\n", req, current->pid);
    if (!req->is_mapped) {
        if (req->type == MMIO) {
            if (copy_to_user(req->addr, cc_data->BAR0_vaddr + DATA_OFFSET, req->length) == 0) {
                return req->length;
            }
        } else {
            if (copy_to_user(req->addr, cc_data->dma_buf, req->length) == 0) {
                return req->length;
            }
        }
    }
    return 0;
}

/*Start device*/
void _start_device(struct user_req *req, u64 dma_cr) {
    u32 offset;
    void *__iomem vaddr = cc_data->BAR0_vaddr;
    pr_info("CC: Initiating the request on device req = %p, pid = %u\n", req, current->pid);

    cc_data->active_req = current;
    if (req->irq_set == IRQ) {
        set_current_state(TASK_INTERRUPTIBLE);
    }

    if (req->type == MMIO) {
        iowrite32(req->length, vaddr + OFF_MMIO_LEN);
        if (req->is_mapped)
            offset = DATA_OFFSET + (u32)req->addr;
        else
            offset = DATA_OFFSET;
        iowrite32(dma_cr, vaddr + OFF_DMA_SR);
        iowrite32(DATA_OFFSET, vaddr + OFF_MMIO_ADDR);
    }
    else if (req->type == DMA) {
        iowrite32(req->length, vaddr + OFF_DMA_LEN);
        iowrite32(cc_data->dma_addr, vaddr + OFF_DMA_ADDR);
        iowrite32(dma_cr, cc_data->BAR0_vaddr + OFF_DMA_SR);
    }

    if (req->irq_set == IRQ) {
        schedule();
    }
    else {
        if (req->type == DMA)
            while(check_dma_busy());
        while(check_device_busy());
    }
}

/*Processes encryption requests*/
void process_data(struct user_req *req, u8 device_op) {
    u64 dma_cr;
    mutex_lock(&device_mutex);
    pr_info("CC: Device locked by: req = %p, pid = %u\n", req, current->pid);
    while(check_device_busy()) {
        mutex_unlock(&device_mutex);
        pr_info("CC: Device unlocked by: req = %p, pid = %u\n, waiting in queue...", req, current->pid);
        wait_event_interruptible_exclusive(cc_data->wait_req, check_device_busy() == 0);
        mutex_lock(&device_mutex);
        pr_info("CC: Device locked by: req = %p, pid = %u\n", req, current->pid);
    }
    dma_cr = set_config(req->type, req->irq_set, device_op, req->key);
    prepare_data(req);
    _start_device(req, dma_cr);
    complete_req(req);
    cc_data->active_req = NULL;
    mutex_unlock(&device_mutex);
    pr_info("CC: Device unlocked by: req = %p, pid = %u\n", req, current->pid);
    wake_up_interruptible(&cc_data->wait_req);
}

/*Gets called when drivers char file is opened*/
static int dev_open(struct inode *inode, struct file *filep) {
    struct user_req *req;
    if (cc_data->mmap_lock.counter) {
        return -EBUSY;
    }

    atomic_inc(&cc_data->device_opened);
    req = kzalloc(sizeof(struct user_req), GFP_KERNEL);
    req->pid = current->pid;
    req->filep = filep;
    req->type = cc_data->cc_sett.sett_type;
    req->irq_set = cc_data->cc_sett.sett_irq_set;
    hash_add(cc_data->cc_req_map, &(req->node), (u64)filep);
    pr_info("CC Open: New req struct added: %u %p\n", current->pid, filep);
    return 0;
}

/*Gets called when drivers char file is closed*/
static int dev_release(struct inode *inode, struct file *filep) {
    struct user_req *req = NULL;
    atomic_dec(&cc_data->device_opened);
    pr_info("CC erer: Closing: %u %p\n", current->pid, filep);
    req = get_user_req(filep);
    if (req) {
        hash_del(&(req->node));
        kfree(req);
        pr_info("CC erer: Entry removed: %u %p\n", current->pid, filep);
    }
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t length, loff_t *offset) {
    
    struct user_req *req = get_user_req(filep);
    if (!req)
        return -EPERM;
    if (!(cc_data->mmap_lock.counter && req->is_mapped))
        return -EPERM;

    pr_info("CC: In read\n");
    if (copy_to_user(buffer, cc_data->BAR0_vaddr + DATA_OFFSET, length) == 0) {
        return length;
    }
    return -EINVAL;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t length, loff_t *offset) {

    struct user_req *req = get_user_req(filep);
    if (!req)
        return -EPERM;
    if (!(cc_data->mmap_lock.counter && req->is_mapped))
        return -EPERM;

    pr_info("CC: In write\n");
    if (copy_from_user(cc_data->BAR0_vaddr + DATA_OFFSET, buffer, length) == 0) {
        pr_info("CC write: Succ %ld\n", length);
        return length;
    }
    return -1;
}

/*Called at time of munmap*/
static void vma_munmap(struct vm_area_struct *vma) {
    int i;
    struct user_req *req = NULL;

    hash_for_each(cc_data->cc_req_map, i, req, node) {
        if (req->pid == current->pid && req->mmap_addr == (void*)vma->vm_start) {
            req->is_mapped = 0;
            req->mmap_addr = 0;
            req->mmap_len = 0;
            break;
        }
    }
    atomic_dec(&cc_data->mmap_lock);

    pr_info("CC: In munmap caller\n");
}

static struct vm_operations_struct cc_vm_ops = {
    .close = vma_munmap,
};

/*mmap syscall handler*/
static int dev_mmap(struct file *filep, struct vm_area_struct *vma) {

    struct user_req *req;
    unsigned long size = (vma->vm_end - vma->vm_start);
    unsigned long pfn;
    
    if (cc_data->mmap_lock.counter)
        return -EBUSY;
    if (size > MAX_SIZE)
        return -EINVAL;
    req = get_user_req(filep);
    if (!req)
        return -1;

    pfn = (pci_resource_start(cc_data->dev, BAR0) + DATA_OFFSET) >> PAGE_SHIFT;
    err = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
    if (err)
        return -EAGAIN;

    vma->vm_ops = &cc_vm_ops;

    atomic_inc(&cc_data->mmap_lock);

    req->is_mapped = 1;
    req->mmap_addr = (void*)vma->vm_start;
    req->mmap_len = size;

    return 0;
}

/*Handles ioctl syscalls*/
static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    u32 key;
    struct user_req *req;
    struct user_data *u_data;
    int ret;

    pr_info("CC: In ioctl %u\n", cmd);

    switch(cmd) {

        case CC_IOCSETMMIO:
            req = get_user_req(filep);
            if (!req)
                return -1;
            req->type = MMIO;
            break;

        case CC_IOCSETDMA:
            req = get_user_req(filep);
            if (!req)
                return -1;
            req->type = DMA;
            break;

        case CC_IOCSETIRQ:
            req = get_user_req(filep);
            if (!req)
                return -1;
            req->irq_set = IRQ;
            break;

        case CC_IOCUNSETIRQ:
            req = get_user_req(filep);
            if (!req)
                return -1;
            req->irq_set = NIRQ;
            break;

        case CC_IOCSETKEYS:
            key = arg & 0xffff;
            req = get_user_req(filep);
            if (!req)
                return -1;
            req->key = key;
            break;

        case CC_IOCENC:

            req = get_user_req(filep);
            if (!req)
                return -1;

            u_data = kzalloc(sizeof(struct user_data), GFP_KERNEL);
            if (copy_from_user(u_data, (void __user*)arg, sizeof(struct user_data)) != 0)
                return -EFAULT;
        
            ret = check_request(req, u_data);
            if (ret)
                return ret;

            if (!req->is_mapped) {
                req->addr = u_data->addr;
                req->length = u_data->length;
            } else {
                req->addr = (void*)(req->mmap_addr - u_data->addr);
                req->length = u_data->length;
            }
            pr_info("CC: Starting encryption...\n");
            process_data(req, ENC);
            pr_info("CC: Encryption completed.\n");
            kfree(u_data);
            break;

        case CC_IOCDEC:
            req = get_user_req(filep);
            if (!req)
                return -1;

            u_data = kzalloc(sizeof(struct user_data), GFP_KERNEL);
            if (copy_from_user(u_data, (void __user*)arg, sizeof(struct user_data)) != 0)
                return -EFAULT;

            ret = check_request(req, u_data);
            if (ret)
                return ret;

            if (!req->is_mapped) {
                req->addr = u_data->addr;
                req->length = u_data->length;
            } else {
                req->addr = (void*)(req->mmap_addr - u_data->addr);
                req->length = u_data->length;
            }
            pr_info("CC: Starting decryption...\n");
            process_data(req, DEC);
            pr_info("CC: Decryption completed.");
            kfree(u_data);
            break;

        case CC_IOCMMAPLEN:
            req = get_user_req(filep);
            if (!req)
                return -1;
            if (!req->is_mapped)
                return -1;
            if ((void*)arg != req->mmap_addr)
                return -1;
            if (copy_to_user((char*)arg, &req->mmap_len, sizeof(u64)) == 0)
                return 0;
            return -1;

        default:
            pr_err("CC: Wrong ioctl parameter passed\n");
            return -EINVAL;
    }
    return 0;
}

static char *dev_devnode(struct device *dev, umode_t *mode) {
    if (mode && dev->devt == cc_data->cc_devno)
        *mode = 0666;
    return NULL;
}

static struct file_operations fops = {
	.owner   = THIS_MODULE,
	.read    = dev_read,
	.write   = dev_write,
    .open    = dev_open,
    .release = dev_release,
    .mmap    = dev_mmap,
    .unlocked_ioctl   = dev_ioctl
};

static irqreturn_t cc_irq_handler(int irq, void *dev_id) {
    u32 data_isr;
    void *__iomem vaddr = cc_data->BAR0_vaddr;

    if (dev_id != &cc_data)
        return IRQ_NONE;

    data_isr = ioread32(vaddr + OFF_ISR);
    iowrite32(data_isr, vaddr + OFF_IRQ_ACK);
    if (cc_data->active_req) {
        wake_up_process(cc_data->active_req);
    }
    pr_info("CC: Interupt handled\n");
    return IRQ_HANDLED;
}

static int create_chrdev(void) {

    struct class *temp_class;
    struct device *temp_device;
    
    err = alloc_chrdev_region(&cc_data->cc_devno, 0, 1, DEVNAME);
    if ( err < 0 ) {
        pr_err("CryptoCard: Cannot get major number\n");
        goto error_regdev;
    }

    cdev_init(&cc_data->cc_cdev, &fops);
    cc_data->cc_cdev.owner = THIS_MODULE;

    err = cdev_add(&cc_data->cc_cdev, cc_data->cc_devno, 1);
    if ( err ) {
        pr_err("CryptoCard: Cannot add device\n");
        unregister_chrdev_region(cc_data->cc_devno, 1);
        goto error_regdev;
    }

    temp_class = class_create(THIS_MODULE, DEVNAME);
    err = PTR_ERR(temp_class);
    if (IS_ERR(temp_class)) {
        pr_err("CryptoCard: Error creating device class\n");
        goto error_class;
    }

    temp_class->devnode = dev_devnode;

    temp_device = device_create(temp_class, NULL, cc_data->cc_devno, NULL, DEVNAME);
    err = PTR_ERR(temp_device);
    if (IS_ERR(temp_device)) {
        pr_err("CryptoCard: Error creating device\n");
        goto error_device;
    }

    atomic_set(&cc_data->device_opened, 0);
    atomic_set(&cc_data->mmap_lock, 0);
    cc_data->cc_class = temp_class;

    return 0;

error_device:
    class_destroy(temp_class);
error_class:
    unregister_chrdev_region(cc_data->cc_devno, 1);
error_regdev:
    return err;
}

static int setup_dma(struct pci_dev *dev) {
    cc_data->dma_buf = dma_alloc_coherent(&dev->dev, DMA_SIZE, &cc_data->dma_addr, GFP_KERNEL);
    pr_info("CC: DMA addr: %p\n", cc_data->dma_buf);
    if (!cc_data->dma_buf) {
        pr_err("CC: dma alloc cohe failed\n");
        return -ENOMEM;
    }
    return 0; 
}

static int free_dma(struct device *dev) {
    if (cc_data->dma_buf) {
        dma_free_coherent(dev, DMA_SIZE, cc_data->dma_buf, cc_data->dma_addr);
        cc_data->dma_buf = NULL;
    }
    return 0;
}

/*------------------SYSFS interface code-------------------------*/
static ssize_t type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buff) {
    return sprintf(buff, "%d\n", cc_data->cc_sett.sett_type);
}

static ssize_t irq_show(struct kobject *kobj, struct kobj_attribute *attr, char *buff) {
    return sprintf(buff, "%d\n", cc_data->cc_sett.sett_irq_set);
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buff) {
    return sprintf(buff, "%d\n", check_device_busy() | check_dma_busy());
}

static ssize_t key_show(struct kobject *kobj, struct kobj_attribute *attr, char *buff) {
    return sprintf(buff, "%d\n", cc_data->cc_sett.sett_key);
}

static ssize_t mmap_show(struct kobject *kobj, struct kobj_attribute *attr, char *buff) {
    return sprintf(buff, "%d\n", cc_data->mmap_lock.counter != 0);
}

/***********************sysfs set functions************************/
static ssize_t type_set(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t count) {
    sscanf(buff, "%hhd", &cc_data->cc_sett.sett_type);
    return count;
}

static ssize_t irq_set(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t count) {
    sscanf(buff, "%hhd", &cc_data->cc_sett.sett_irq_set);
    return count;
}

static ssize_t key_set(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t count) {
    sscanf(buff, "%d", &cc_data->cc_sett.sett_key);
    return count;
}

static struct kobj_attribute cc_type_attr = __ATTR(memop_type, 0644, type_show, type_set);
static struct kobj_attribute cc_irq_attr = __ATTR(irq, 0644, irq_show, irq_set);
static struct kobj_attribute cc_status_attr = __ATTR_RO(status);
static struct kobj_attribute cc_key_attr = __ATTR(key, 0644, key_show, key_set);
static struct kobj_attribute cc_is_mmap_attr = __ATTR_RO(mmap);

static struct attribute *cc_attrs[] = {
    &cc_type_attr.attr,
    &cc_irq_attr.attr,
    &cc_status_attr.attr,
    &cc_key_attr.attr,
    &cc_is_mmap_attr.attr,
    NULL,
};

static int create_sysfs(void) {
    int err;

    cc_data->cc_attr_group.attrs = cc_attrs;
    cc_data->cc_attr_group.name = DEVNAME;

    err = sysfs_create_group(kernel_kobj, &cc_data->cc_attr_group);
    if (unlikely(err)) {
        pr_info("CryptoCard: Can't create sysfs\n");
        return -1;
    }

    return 0;

}
/*------------------SYSFS end-------------------------*/

static int cc_probe(struct pci_dev *dev, const struct pci_device_id *id) {

    void *__iomem bar0_virt;

    if ( pci_enable_device(dev) ) {
        pr_err("CryptoCard: Error enabling PCI device\n");
        return -ENODEV;
    }
    pci_set_master(dev);

    err = pci_request_region(dev, BAR0, DEVNAME);
    if (err) {
        pr_err("CryptoCard: Requesting Region failed\n");
        return -EBUSY;
    }

    cc_data = kzalloc(sizeof(struct driver_dev), GFP_KERNEL);
    if (!cc_data) {
        pr_err("CryptoCard: Memory allocation failed!\n");
        return -ENOMEM;
    }
    cc_data->dev = dev;

    bar0_virt = pci_iomap(dev, BAR0, BAR0_SIZE);   //BAR0 virtual address
    cc_data->BAR0_vaddr = bar0_virt;
    pr_info("CryptoCard: BAR0 Virt Add: 0x%p, Len: %d\n", bar0_virt, BAR0_SIZE);
    
    //Setting up IRQ
    cc_data->irq = dev->irq;
    if ( request_irq((u32)dev->irq, cc_irq_handler, IRQF_SHARED, CC_DRIVER_NAME, (void*)&cc_data) ) {
        pr_info("CryptoCard: Error registering interrupt handler\n");
    //    goto
    }
    iowrite32(0, cc_data->BAR0_vaddr + OFF_IRQ_RAISE);

    /*DMA setup*/
    err = dma_set_coherent_mask(&dev->dev, DMA_BIT_MASK(32));
    if (err)
        pr_err("CryptoCard: DMA set mask failed: %d\n", err);

    err = setup_dma(dev);
    if (err)
        pr_info("CryptoCard: Error setting up DMA\n");

    /*Initializing wait queue*/
    init_waitqueue_head(&cc_data->wait_req);

    /*Initializing hash table*/
    hash_init(cc_data->cc_req_map);


    if (create_chrdev()) {
        pr_err("CryptoCard: Error creating char dev file\n");
        //goto driver_dev_err;
    }

    create_sysfs();
    
    pr_info("CC IOC: CC_IOCENC:%ld\n", CC_IOCENC);
    pr_info("CC IOC: CC_IOCDEC:%ld\n", CC_IOCDEC);
    pr_info("CC IOC: CC_IOCSETDMA:%d\n", CC_IOCSETDMA);
    pr_info("CC IOC: CC_IOCSETMMIO:%d\n", CC_IOCSETMMIO);
    pr_info("CC IOC: CC_IOCSETIRQ:%d\n", CC_IOCSETIRQ);
    pr_info("CC IOC: CC_IOCUNSETIRQ:%d\n", CC_IOCUNSETIRQ);
    pr_info("CC IOC: CC_IOCSETKEYS:%ld\n", CC_IOCSETKEYS);
    pr_info("CC IOC: CC_IOCMMAPLEN:%ld\n", CC_IOCMMAPLEN);

    pr_info("CryptoCard: Probing done successfully\n");
    init_default_driver();
//goto driver_dev_err:
//    kfree();

//goto 
    return 0;
}

void cc_remove(struct pci_dev *dev) {
    free_irq(cc_data->irq, (void*)&cc_data);
    device_destroy(cc_data->cc_class, cc_data->cc_devno);
    class_destroy(cc_data->cc_class);
    unregister_chrdev_region(cc_data->cc_devno, 1);
    sysfs_remove_group(kernel_kobj, &cc_data->cc_attr_group);
    free_dma(&dev->dev);
    pci_iounmap(dev, cc_data->BAR0_vaddr);
    pci_release_region(dev, BAR0);
    kfree(cc_data);
	pr_info("CryptoCard: Removing driver\n");
}

static struct pci_driver cc_driver = {
    .name = CC_DRIVER_NAME,
    .id_table = module_ids,
    .probe = cc_probe,
    .remove = cc_remove
};

int init_module(void) {
    pr_info("CryptoCard: Initialising module\n");
	return pci_register_driver(&cc_driver);
}

void cleanup_module(void) {
    pci_unregister_driver(&cc_driver);
    pr_info("CryptoCard: Removing the module\n");
}

MODULE_DESCRIPTION("CryptoCard module");
MODULE_AUTHOR("Ketan Chaturvedi");
MODULE_LICENSE("GPL");