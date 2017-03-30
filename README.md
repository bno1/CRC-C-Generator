# CRC C Code Generator
Generates a C function that computes a CRC function.
The CRC function can be customized by controlling:
 - The generator polynomial
 - Initial CRC value
 - Xor value before returning CRC
 - Input reflection (bit order)
 - Output reflection (byte order)

The C code uses a pregenerated lookup table of size 4, 16 or 256 (2 bits, 4 bits
or 8 bits for index).

# Requirements
Python 2.6 or greater (compatible with python3).

# Usage
`./crc_c_generator.py [OPTIONS] POWERS [HEADER_FILE] SOURCE_FILE`

Where POWERS represents the space separated list of powers in the CRC polynomial, in any order.

The greatest power determines the size in bits of the CRC code.


OPTIONS:
```
--tb=n - number of bits used by the lookup table.
    Valid values:
    2 - 4 entries, 4 lookups per byte
    4 - 16 entries, 2 lookups per byte
    8 - 256 entries, 1 lookup per byte (default)

--ri - input is reflected, bits will be processes starting with LSB rather than MSB, default off

--ro - output is reflected, default off

--xoro=n - value to xor with before returning, default 0

--iv=n - initial value of the crc, default 0
    n can be in base 10 (ex. 65535), base 16 (ex. 0xffff) or base 2 (ex. 0b1111111111111111)

--fn=name - name of the function that will be generated, "crc" by default
```

Example that generates code for CRC-CCITT (Kermit) with a byte-indexed table:

`./crc_c_generator.py --fn=kermit --ri --ro 16 12 5 0 kermit.h kermit.c`

kermit.h
```C
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t kermit(const uint8_t *buffer, size_t count);

#ifdef __cplusplus
} /* extern "C" */
#endif
```

kermit.c
```C
#include "kermit.h"

uint16_t kermit(const uint8_t *buffer, size_t count) {
    // x^16 + x^12 + x^5 + 1
    // reflected input: True
    // reflected output: True
    // init crc: 0x0
    // xor out: 0x0

    static const uint16_t lt[256] = {
        0x0000, 0x1189, 0x2312, 0x329b,
        ....
    };
    uint16_t r = 0x0;

    while (count > 0) {
        r = (r >> 8) ^ lt[((uint8_t)r ^ *buffer) & 0xff];
        buffer++;
        count--;
    }

    r = (r >> 8) | ((r & 0xff) << 8);

    return r;
}
 ```

This code is licensed under the MIT License
