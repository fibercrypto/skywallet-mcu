#include "error_common.h"

#include <messages.pb.h>
#include "firmware/fsm_impl.h"
#include "messages.h"
#include "string.h"
#include "usb.h"
#include "setup.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void msg_out_panic(const char *panic_msg) {
    RESP_INIT(Failure)
    resp->has_msg_type = false;
    resp->has_code = true;
    resp->code = FailureType_Failure_FirmwarePanic;
    if (panic_msg != 0) {
        resp->has_message = true;
        strlcpy(resp->message, panic_msg, sizeof(resp->message));
    }
    msg_write(MessageType_MessageType_Failure, resp);
#if !defined(EMULATOR) || EMULATOR != 1
    usbFlush();
#endif //  !defined(EMULATOR) || EMULATOR != 1
}

static char *panic_msg = NULL;
char *get_panic_msg(void) {
    return panic_msg;
}

void set_panic_msg(char *msg) {
  panic_msg = msg;
}
