#ifndef ANALYZER_H
#define ANALYZER_H

int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md, Elf32_Word text_size);
uint16_t get_machine_type(int fd);
void print_instructions(const uint8_t *buf, uint32_t addr, uint32_t len);
int authenticate(char *username, int password_int);
void invalidAuth();
int main(int argc, char **argv);

#endif
