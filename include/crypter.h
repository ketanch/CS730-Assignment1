#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#ifndef CRYPTER_H_
#define CRYPTER_H_

#define ADDR_PTR void*
#define DEV_HANDLE int
#define SET 1
#define UNSET 0
#define TRUE 1
#define FALSE 0
#define ERROR -1
#define KEY_COMP uint8_t

typedef enum {INTERRUPT, DMA} config_t;

struct driver_req {
    uint8_t is_mapped;
    ADDR_PTR addr;
    uint64_t length;
};

DEV_HANDLE create_handle();

void close_handle(DEV_HANDLE cdev);

int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped);

int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped);

int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b);

int set_config(DEV_HANDLE cdev, config_t type, uint8_t value);

ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size);

void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr);

#define CC_IOCENC 3225982464
#define CC_IOCDEC 3225982465
#define CC_IOCSETDMA 38402
#define CC_IOCSETMMIO 38403
#define CC_IOCSETIRQ 38404
#define CC_IOCUNSETIRQ 38405
#define CC_IOCSETKEYS 1074042374
#define CC_IOCMMAPLEN 2148046343

#define MAX_DEV_INP (1 << 15)
#define MAX_INP (1 << 20)

#endif
