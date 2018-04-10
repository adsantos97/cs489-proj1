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
#include "simple_bin_proto.h"
#include "analyzer.h"

extern int DoubleSum(int a, int b);

// Compile me: gcc proj1_example.c -o example -lelf -lcrypto -lcapstone
// I'll drop a nice binary file on disk.

#define DISASSEMBLE_START_ADDR 0x08048310
#define MAX_BUF_SIZE 0x1000

// Construct a structured data buffer
int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md)
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
    return sizeof(FileHeader) + ((FileHeader *)record_buf)->data_length;
}

Elf32_Xword get_text_size(int fd)
{
    Elf *e;  // ELF
    Elf_Scn *scn;  // Section index struct
    Elf_Data *data;
    GElf_Shdr shdr;  // Section struct
    char *name;
    uint8_t *p;
    size_t shstrndx;
    Elf32_Xword text_size;

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
    text_size = (Elf32_Xword)shdr.sh_size;
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
 * purpose: user authentication
 * input: username - username given by the user
 *        password_int - password given by the user
 * returns: -1 if fail, otherwise 0 if not fail
 */
int authenticate(char *username, int password_int)
{
   if (strcmp(username, "Spongebob Squarepants\n") == 0)
     if (password_int % 5 == 0)
       return 0;
     else
     {
       invalidAuth();
       return -1;
     }
   else
   {
     invalidAuth();
     return -1;
   } 
}

// purpose: prints out no access statement
void invalidAuth()
{
   puts("No access for you!");
}

int main(int argc, char **argv)
{
    int fd, i;
    uint16_t machine;
    Elf32_Xword text_size;
    uint8_t md[MD5_DIGEST_LENGTH];
    FILE *outfile;
    uint8_t outbuf[MAX_BUF_SIZE];
    int record_size;
    char *inputfile = NULL;  
    char *username = NULL;
    char *password = NULL;
    int password_int;

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
   
    puts("Username: ");
    username = malloc (sizeof(char) * 101);
    fgets(username, 100, stdin);
    puts("Password: ");
    password = malloc (sizeof(char) * 101);
    fgets(password, 100, stdin);
    password_int = atoi(password);

    if(authenticate(username, password_int) == 0)
    { 

	    fileptr = fopen(inputfile, "rb");  // Open the file in binary mode
	    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	    filelen = ftell(fileptr);             // Get the current byte offset in the file
	    rewind(fileptr);                      // Jump back to the beginning of the file

	    filesize= (filelen+1)*sizeof(const uint8_t);
	    data = (uint8_t *)malloc(filesize); // Enough memory for file + \0
	      
	    fread(data, filelen, 1, fileptr); // Read in the entire file
	    fclose(fileptr); // Close the file

	    printf("Assembly function: (%d + %d) * 2 = %d\n", 1,2,DoubleSum(1,2));

	    // open yourself
	    if ((fd = open(argv[1], O_RDONLY, 0)) < 0)
	    {
		err(EXIT_FAILURE, "open %s failed\n", argv[1]);
	    }

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

	    record_size = make_record(outbuf, argv[1], machine, md);

	    outfile = fopen("mydata.bin", "ab+");
	    fwrite(outbuf, sizeof(uint8_t), record_size, outfile);
	    fflush(outfile);
	    fclose(outfile);
    }

    return EXIT_SUCCESS;

}
