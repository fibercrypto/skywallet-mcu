#ifndef TINYFIRMWARE_ERRORCOMMON_H
#define TINYFIRMWARE_ERRORCOMMON_H

void msg_out_panic(const char *panic_msg);
char *get_panic_msg(void);
void set_panic_msg(char *msg);

#endif //  TINYFIRMWARE_ERRORCOMMON_H
