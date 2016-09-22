# CRC C Code Generator
Generates C function that computes a CRC function.
The CRC function can be customized by controlling:
 - The generator polynomial
 - Initial CRC value
 - Xor value before returning CRC
 - Input reflection (bit order)
 - Output reflecrtion (byte order)

The C code uses a pregenerated lookup table of size 4, 16 or 256 (2 bits, 4 bits
or 8 bits for index).

# Usage
```
./crc_c_generator.py [OPTIONS] POWERS [HEADER_FILE] SOURCE_FILE
Where POWERS represents the space separated list of powers in the CRC polynomial, in any order.
The greatest power determines the size in bits of the CRC code.

OPTIONS:

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

Example that generates code for CRC-CCITT (Kermit) with a byte-indexed table:
./crc_c_generator.py --fn=kermit --ri --ro 16 12 5 0 kermit.h kermit.c

kermit.h
  #pragma once
  
  #include <stdint.h>
  #include <stddef.h>
  
  #ifdef __cplusplus
  extern "C" {
  #endif
  
  uint16_t kermit(const uint8_t *buffer, size_t count);
  
  #ifdef __cplusplus
  } /* extern "C" */

kermit.c
  
```

This code is licensed under the MIT License
