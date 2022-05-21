#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <gen.h>

int main()
{

  int file_desc = 0, file_size = 0;
  void *buffer =  map_file(&file_desc, &file_size);
  unsigned int chunk_size = (1024*1024);
  int r = 0;

  char *actual_buffer = (char *) malloc(chunk_size);
  strncpy(actual_buffer, buffer, chunk_size);

  int key_a = 10, key_b = 20;
  int a[6];

  a[0] = create_device_handle(UNSET, UNSET, key_a, key_b);
  a[1] = create_device_handle(UNSET, SET,key_a+1, key_b+1);
  a[2] = create_device_handle(SET, SET, key_a+2, key_b+2);
  a[3] = create_device_handle(SET, UNSET, key_a+3, key_b+3);


  char *check_buffer = create_encrpyted_buffer(actual_buffer, key_a, key_b, chunk_size);

  r = encrypt(a[0], actual_buffer, chunk_size, 0);

  if(!isValid(actual_buffer, check_buffer, chunk_size))
  {
    printf("Failed 0 err = %d\n", r);
    printf("Testcase failed\n");
    exit(0);
  }

  for(int i =1; i<=12; i++)
  {
      printf("Index %d\n", i);
      int fd_index = i % 4;
      encryptMessage(check_buffer, chunk_size, (key_a + fd_index), (key_b+fd_index));
      //printf("ENc buff = %s\n", actual_buffer);
      encrypt(a[fd_index], actual_buffer, chunk_size, 0);
      if(!isValid(actual_buffer, check_buffer, chunk_size))
      {
      	printf("Failed 1\n");
        printf("Testcase failed\n");
        exit(0);
      }
  }

  for(int i = 12; i>=1; i--)
  {
      int fd_index = i % 4;
      decryptMessage(check_buffer, chunk_size, (key_a + fd_index), (key_b+fd_index));
      decrypt(a[fd_index], actual_buffer, chunk_size, 0);
      if(!isValid(actual_buffer, check_buffer, chunk_size))
      {
      	printf("Failed 2\n");
        printf("Testcase failed\n");
        exit(0);
      }
  }

  printf("Testcase passed\n");

  return 0;

}
