#ifndef ANALYZER_H
#define ANALYZER_H

int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md, Elf32_Word text_size, Elf32_Half num_sections);
Elf32_Word get_text_size(int fd);
Elf32_Half get_num_sections(int fd);
uint16_t get_machine_type(int fd);
void verify_format(int fd);
void print_instructions(const uint8_t *buf, uint32_t addr, uint32_t len);
char *new_username(char *username);
int authenticate(char *username, int password_int, int sig);
void invalidAuth(int signal);
void initTermios(int echo);
void resetTermios(void);
char getch_(int echo);
char getch(void);
char getche(void);
int main(int argc, char **argv);

#endif
