CC = gcc
CFLAGS = -g

LIB=lib
BIN=bin
OBJ=obj
SRC=src
LIB_SRC=common
INC=inc
LIB_OBJ=lib


HDRS=$(shell ls $(INC)/*.h)

all: crdir generic dma mmio mmap multiprocess

crdir:
	cp ../include/crypter.h ./inc/crypter.h
	mkdir -p lib
	cp ../lib/libcrypter.so ./lib/libcrypter.so
	HDRS=$(shell ls $(INC)/*.h)
	mkdir -p bin/Generic
	mkdir -p bin/MMIO/IRQ
	mkdir -p bin//MMIO/withoutIRQ
	mkdir -p bin/DMA/IRQ
	mkdir -p bin//DMA/withoutIRQ
	mkdir -p bin/MMAP/IRQ
	mkdir -p bin//MMAP/withoutIRQ
	mkdir -p bin/MultiProcess
	mkdir -p obj/Generic
	mkdir -p obj/MMIO/IRQ
	mkdir -p obj//MMIO/withoutIRQ
	mkdir -p obj/DMA/IRQ
	mkdir -p obj//DMA/withoutIRQ
	mkdir -p obj/MMAP/IRQ
	mkdir -p obj//MMAP/withoutIRQ
	mkdir -p obj/MultiProcess

generic: $(BIN)/Generic/test1

multiprocess: $(BIN)/MultiProcess/test1

dma: dma_irq dma_wirq

dma_irq: $(BIN)/DMA/IRQ/test1

dma_wirq: $(BIN)/DMA/withoutIRQ/test1

mmap: mmap_irq mmap_wirq

mmap_irq: $(BIN)/MMAP/IRQ/test1

mmap_wirq: $(BIN)/MMAP/withoutIRQ/test1


mmio: mmio_irq mmio_wirq

mmio_irq: $(BIN)/MMIO/IRQ/test1

mmio_wirq: $(BIN)/MMIO/withoutIRQ/test1


$(BIN)/%: $(OBJ)/%.o $(LIB_OBJ)/gen.o
	$(CC) -o $@ -I$(INC) $^ -L$(LIB) -lcrypter -lpthread

$(OBJ)/%.o: $(SRC)/%.c $(HDRS)
	$(CC) -c -I$(INC) $< -o $@

# library: $(LIB)/libcommon.so
#
# $(LIB)/libcommon.so: $(LIB_OBJ)/gen.o
# 	gcc -shared -o $@ $^

$(LIB_OBJ)/%.o: $(LIB_SRC)/%.c $(HDRS)
	mkdir -p lib
	$(CC) -c -I$(INC) $< -o $@

%-pa-cs730.tar.gz:	clean
	tar cf - `find . -type f | grep -v '^\.*$$' | grep -v '/CVS/' | grep -v '/\.svn/' | grep -v '/\.git/' | grep -v '[0-9].*\.tar\.gz' | grep -v '/submit.token$$'` | gzip > $@

.PHONY: prepare-submit
prepare-submit: $(RNO)-pa-cs730.tar.gz

.PHONY: clean
clean:
	rm -rf  $(OBJ) $(BIN) $(LIB) $(INC)/crypter.h
