#include <crypter.h>

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
	int fd = open("/dev/cryptocard", O_RDWR);
	return fd;
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
	close(cdev);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	struct driver_req req;
	int ret;
	if (length > MAX_INP)
		return -1;
	while (length > MAX_DEV_INP) {
		req.addr = addr;
		req.is_mapped = isMapped;
		req.length = MAX_DEV_INP;
		ret = ioctl(cdev, CC_IOCENC, &req);
		if (ret) 
			return ret;
		length -= MAX_DEV_INP;
		addr += MAX_DEV_INP;
	}
	req.addr = addr;
	req.is_mapped = isMapped;
	req.length = length;
	ret = ioctl(cdev, CC_IOCENC, &req);
	return ret;
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	struct driver_req req;
	int ret;
	if (length > MAX_INP)
		return -1;
	while (length > MAX_DEV_INP) {
		req.addr = addr;
		req.is_mapped = isMapped;
		req.length = MAX_DEV_INP;
		ret = ioctl(cdev, CC_IOCDEC, &req);
		if (ret)
			return ret;
		length -= MAX_DEV_INP;
		addr += MAX_DEV_INP;
	}
	req.addr = addr;
	req.is_mapped = isMapped;
	req.length = length;
	ret = ioctl(cdev, CC_IOCDEC, &req);
	return ret;
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
	int ret = ERROR;
	int key = (a << 8) | b;
	ret = ioctl(cdev, CC_IOCSETKEYS, key);
	return ret;
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
	int ret = ERROR;
	unsigned long flag;
	switch(type) {
		case DMA:
			if (value == SET) {
				flag = CC_IOCSETDMA;
				ret = 0;
			}
			else if (value == UNSET) {
				flag = CC_IOCSETMMIO;
				ret = 0;
			}
			break;
		case INTERRUPT:
			if (value == SET) {
				flag = CC_IOCSETIRQ;
				ret = 0;
			}
			else if (value == UNSET) {
				flag = CC_IOCUNSETIRQ;
				ret = 0;
			}
			break;
	}
	if (!ret) {
		ret = ioctl(cdev, flag);
	}
	return ret;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
	ADDR_PTR ret = mmap(NULL, size, PROT_WRITE, MAP_SHARED, cdev, 0);
	if (ret == MAP_FAILED)
		ret = NULL;
	return ret;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
	uint64_t mmap_len = (uint64_t)addr;
	ioctl(cdev, CC_IOCMMAPLEN, &mmap_len);
	munmap(addr, (size_t)mmap_len);
}
