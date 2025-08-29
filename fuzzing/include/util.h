#pragma once

// Fuzzing-specific util.h
// Provides minimal utility functions needed for CBOR parsing

#ifdef FUZZING_BUILD

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Mock utility functions that might be referenced in cborStrParsing.c
// These will be implemented in util_stub.c as needed

#else

// Include the real util.h when not fuzzing
#include "../src/common/util.h"

#endif // FUZZING_BUILD

```

```

