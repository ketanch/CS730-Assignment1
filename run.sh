#!/bin/bash

sshpass -p "ketan" scp -P 5555 -r drivers/ ketan@localhost:/home/ketan/Desktop/Ass1
sshpass -p "ketan" scp -P 5555 src/crypter.c ketan@localhost:/home/ketan/Desktop/tests/crypter.c
sshpass -p "ketan" scp -P 5555 include/crypter.h ketan@localhost:/home/ketan/Desktop/tests/crypter.h
sshpass -p "ketan" scp -P 5555 -r mytest/* ketan@localhost:/home/ketan/Desktop/tests
