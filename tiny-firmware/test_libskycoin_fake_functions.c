#include <stddef.h>
#include <time.h>
#include <stdlib.h>

void setup(void) { srand(time(NULL)); }

void teardown(void) {
  // TODO make a mem clean up like here
  // https://github.com/skycoin/libskycoin/blob/99358b30b9363ec2d663ee12de9e1166ae9d5ea4/lib/cgo/tests/testutils/libsky_testutil.c#L241
}
