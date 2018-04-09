#ifndef PROJ_1_H
#define PROJ_1_H

int make_record(uint8_t *record_buf, char *name, uint16_t machine, uint8_t *md);
uint16_t get_machine_type(int fd);
void print_instructions(const uint8_t *buf, uint32_t addr, uint32_t len);
int authenticate(char *username, int password_int);
void invalidAuth();
int main(int argc, char **argv);

#endif
