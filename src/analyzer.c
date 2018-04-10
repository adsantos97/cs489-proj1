#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <openssl/md5.h>
#include <capstone/capstone.h>
#include <termios.h>
#include "simple_bin_proto.h"
#include "analyzer.h"

static struct termios old, new;

extern int DoubleSum(int a, int b);

#define DISASSEMBLE_START_ADDR 0x08048310
#define MAX_BUF_SIZE 0x1000

// Construct a structured data buffer
int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md,
                Elf32_Word text_size)
{
    uint8_t *buf_ptr = record_buf;
    strncpy(((FileHeader *)record_buf)->file_name, name, sizeof(((FileHeader *)record_buf)->file_name)-1);
    buf_ptr += sizeof(FileHeader);
    ((MachineRecord *)buf_ptr)->et = MACHINE_RECORD;
    ((MachineRecord *)buf_ptr)->machine = machine;
    ((FileHeader *)record_buf)->data_length += sizeof(MachineRecord);
    buf_ptr += sizeof(MachineRecord);
    ((MD5Record *)buf_ptr)->et = MD5_RECORD;
    memcpy(&((MD5Record *)buf_ptr)->md5, md, sizeof((MD5Record *)buf_ptr)->md5);
    ((FileHeader *)record_buf)->data_length += sizeof(MD5Record);
    buf_ptr += sizeof(MD5Record);
    ((TextSizeRecord *)buf_ptr)->et = TEXT_SIZE_RECORD;
    ((TextSizeRecord *)buf_ptr)->text_size = text_size;
    ((FileHeader *)record_buf)->data_length += sizeof(TextSizeRecord);
    return sizeof(FileHeader) + ((FileHeader *)record_buf)->data_length;
}

/*
 * purpose: get the size of .text
 * input: fd - file descriptor
 * return: size of .text
 */
Elf32_Word get_text_size(int fd)
{
    Elf *e;  // ELF
    Elf_Scn *scn;  // Section index struct
    Elf_Data *data;
    GElf_Shdr shdr;  // Section struct
    char *name;
    uint8_t *p;
    size_t shstrndx;
    Elf32_Word text_size;

    // initialize libelf
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        errx(EXIT_FAILURE, "ELF library init failure: %s\n", elf_errmsg(-1));
    }

    // Initialize the elf object
    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        errx(EXIT_FAILURE, "ELF begin failed: %s\n", elf_errmsg(-1));
    }

    if (elf_getshdrstrndx(e, &shstrndx) != 0)
    {
       errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1));
    }

    // Get text section
    scn = NULL;
    
    data = NULL;
    while ((scn = elf_nextscn(e,scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1));

        if ((name = elf_strptr(e, shstrndx, shdr.sh_name)) == NULL)
            errx(EXIT_FAILURE, "elf_strptr() failed: %s", elf_errmsg(-1));

        if (strcmp(name, ".text") == 0)
        {
            if ((data = elf_getdata(scn, 0)) == NULL)
                errx(EXIT_FAILURE, "elf_getdata() failed: %s", elf_errmsg(-1));
            p = (uint8_t *) data->d_buf;
            break;
        }
    }

    printf("Size of .text section is 0x%06x\n", shdr.sh_size);
    text_size = (Elf32_Word)shdr.sh_size;
    elf_end(e);

    return text_size;
}

/*
 * purpose: get the machine architecture this ELF object is for
 * input: fd - file descriptor
 * return: machine type
 */
uint16_t get_machine_type(int fd)
{
    Elf *e;
    GElf_Ehdr ehdr;
    uint16_t machine;

    // initialize libelf
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        errx(EXIT_FAILURE, "ELF library init failure: %s\n", elf_errmsg(-1));
    }

    // Initialize the elf object
    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        errx(EXIT_FAILURE, "ELF begin failed: %s\n", elf_errmsg(-1));
    }
    
    // Get the header
    if (gelf_getehdr(e, &ehdr) == NULL)
    {
        errx(EXIT_FAILURE, "getehdr failed: %s\n", elf_errmsg(-1));
    }

    printf("Machine type is 0x%x\n", ehdr.e_machine);
    machine = (uint16_t)ehdr.e_machine;
    elf_end(e);

    return machine;
}

/* purpose: verify the format of the binary file before proceeding
 * input: fd - file descriptor
 * returns: nothing
 */
void verify_format(int fd)
{
    Elf *e;
    GElf_Ehdr ehdr;

    // initialize libelf
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        errx(EXIT_FAILURE, "ELF library init failure: %s\n", elf_errmsg(-1));
    }

    // Initialize the elf object
    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        errx(EXIT_FAILURE, "ELF begin failed: %s\n", elf_errmsg(-1));
    }
    
    // Get the header
    if (gelf_getehdr(e, &ehdr) == NULL)
    {
        errx(EXIT_FAILURE, "getehdr failed: %s\n", elf_errmsg(-1));
    }
}

/*
 * purpose: prints out the disassembly (i.e. disassembled binary file)
 * input: buf - buffer
 *        addr - start address
 *        len - length of 
 * returns: nothing - prints out disassembly
 */
void print_instructions(const uint8_t *buf, uint32_t addr, uint32_t len)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
        printf("ERROR: Failed to initialize engine!\n");
        return;
    }

    count = cs_disasm(handle, (unsigned char *)buf, len, addr, 0, &insn);
    if (count)
    {
        size_t j;

        for (j = 0; j < count; j++) {
            printf("%p: %s\t\t%s\n", (void *) ((uint32_t)insn[j].address), insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return;
}

/*
 * purpose: conversion of username
 * input: username
 * returns: new username
 */
char *new_username(char *username)
{
   char *new = malloc(strlen(username) +1);

   int i = 0;

   while(username[i] != '\0')
   {
     if(username[i] == DoubleSum(20, 1))
       new[i] = 's';
     else if(username[i] == DoubleSum(15, 3))
       new[i] = 'p';
     else if(username[i] == 115)
       new[i] = 'S';
     else if(username[i] == DoubleSum(28, 28))
       new[i] = 'P'; 
     else
       new[i] = username[i];

     i++;
   }

   return new;
}

/*
 * purpose: user authentication
 * input: username - username given by the user
 *        password_int - password given by the user
 *        sig - signal passed 
 * returns: -1 if fail, otherwise 0 if not fail
 */
int authenticate(char *username, int password_int, int sig)
{
   if(strcmp(username, "spongebob squarepants\n") == 0)
   {
     if(password_int % 5 == 0)
       return 0;
     else
     {
       invalidAuth(sig);
       return -1;
     }
   }
   else
   {
     invalidAuth(sig);
     return -1;
   } 
}

/* purpose: prints out no access statement
 * input: signal - signal to print statement
 * return: nothing - print statement
 */
void invalidAuth(int signal)
{
   if (signal == 0)
     puts("No access for you!");
   else
     puts("");
}

/* Initialize new terminal i/o settings */
void initTermios(int echo) 
{
  tcgetattr(0, &old); /* grab old terminal i/o settings */
  new = old; /* make new settings same as old settings */
  new.c_lflag &= ~ICANON; /* disable buffered i/o */
  if (echo) {
      new.c_lflag |= ECHO; /* set echo mode */
  } else {
      new.c_lflag &= ~ECHO; /* set no echo mode */
  }
  tcsetattr(0, TCSANOW, &new); /* use these new terminal i/o settings now */
}

/* Restore old terminal i/o settings */
void resetTermios(void) 
{
  tcsetattr(0, TCSANOW, &old);
}

/* Read 1 character - echo defines echo mode */
char getch_(int echo) 
{
  char ch;
  initTermios(echo);
  ch = getchar();
  resetTermios();
  return ch;
}

/* Read 1 character without echo */
char getch(void) 
{
  return getch_(0);
}

/* Read 1 character with echo */
char getche(void) 
{
  return getch_(1);
}

int main(int argc, char **argv)
{
    int fd, i;
    uint16_t machine;
    Elf32_Word text_size;
    uint8_t md[MD5_DIGEST_LENGTH];
    FILE *outfile;
    uint8_t outbuf[MAX_BUF_SIZE];
    int record_size;
    char *inputfile = NULL;  
    char *username, *password, *new;
    char c;
    int password_int, auth;
    int sig = 0;

    FILE *fileptr;
    uint8_t *data;
    long filelen;
    long filesize;

    if(argc == 2){
        inputfile = argv[1];
    }else{
        printf("This program requires a single argument: <filename>\n");
    	exit(-1);
    }
 
    username = malloc (sizeof(char) * 101);
    password = malloc (sizeof(char) * 101);

    printf("Hit enter key to start analyzing.\n");

    // backdoor
    c = getch();
    if (c == 'q')
      sig = 1;    

    // authentication
    if (c != 'q')
    {
        do
        { 
            puts("Username: ");
            fgets(username, 100, stdin);
            puts("Password: ");
            fgets(password, 100, stdin);
            new = new_username(username);
            password_int = atoi(password);
            auth = authenticate(new, password_int, sig);
            
        } while (auth != 0);
    }

    // retrieve and display information on binary if authentication is correct
    if(auth == 0 || c == 'q')
    { 
        fileptr = fopen(inputfile, "rb");  // Open the file in binary mode
        fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
        filelen = ftell(fileptr);             // Get the current byte offset in the file
        rewind(fileptr);                      // Jump back to the beginning of the file

        filesize= (filelen+1)*sizeof(const uint8_t);
        data = (uint8_t *)malloc(filesize); // Enough memory for file + \0
          
        fread(data, filelen, 1, fileptr); // Read in the entire file
        fclose(fileptr); // Close the file

        // open yourself
        if ((fd = open(argv[1], O_RDONLY, 0)) < 0)
        {
	    err(EXIT_FAILURE, "open %s failed\n", argv[1]);
        }

        verify_format(fd);
        machine = get_machine_type(fd);
        text_size = get_text_size(fd);

        if (!MD5(data, filesize, md))
        {
	    err(EXIT_FAILURE, "MD5 failed\n");
        }

        printf("MD5: ");

        for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        {
	    printf("%02x", md[i]);
        }
        printf("\n");

        //print_instructions(data, DISASSEMBLE_START_ADDR, filesize);

        close(fd);

        memset(outbuf, 0, sizeof(outbuf));

        record_size = make_record(outbuf, argv[1], machine, md, text_size);

        outfile = fopen("../bin/mydata.bin", "ab+");
        fwrite(outbuf, sizeof(uint8_t), record_size, outfile);
        fflush(outfile);
        fclose(outfile);
    }

    return EXIT_SUCCESS;

}
