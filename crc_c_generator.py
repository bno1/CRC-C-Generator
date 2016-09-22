#!/usr/bin/env python

'''
CRC C Code Generator
Generates C function that computes a crc function. The crc can be customised by
specifing:
    - the generator polynomial
    - initial crc value
    - xor value before returning crc
    - input reflection (bit order)
    - output reflecrtion (byte order)

The C code uses a pregenerated lookup table of size 4, 16 or 256 (2 bits, 4 bits
or 8 bits for index)

Author: bno1
Git url: https://github.com/bno1/CRC-C-Generator
Date: 21 Sep 2016

This code is licensed under the MIT License
'''

from __future__ import print_function
import re
import sys

FLAG_REFIN = 1 # reflected input
FLAG_REFOUT = 2 # reflected output
USAGE = '''Usage: %(cmd)s [OPTIONS] POWERS [HEADER_FILE] SOURCE_FILE
Where <POWERS> represents the space separated list of powers in the CRC polynomial, in any order. The greatest power determines the size in bits of the CRC code.

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
%(cmd)s --ri --ro 16 12 5 0 kermit.h kermit.c
'''

def parse_cmdline(argv):
    '''
    argv format: [<invoking command>, ['--tb=n,'] <POWERS>, [<h_file>,] <c_file>], see Usage below
    Parses the command line arguments and returns a dictionary containing:
    {
        'error': true if an error occured
        'error_description':
        'table_bits': number of bits used to index the lookup table
        'generator': numeric value of the CRC generator
        'powers': descending list of powers in the CRC polynomial
        'header_file': C .h file name
        'source_file': C .c file name
        'init_crc': crc initial value
        'xoro': value to xor with the crc before returning
        'flags': a combination of FLAG_* constants
        'funcname': name of the function that will be generated
    }
    '''

    res = {
        'error': False,
        'error_description': '',
        'table_bits': 8,
        'generator': 0,
        'powers': [],
        'header_file': None,
        'source_file': None,
        'init_crc': 0,
        'xoro': 0,
        'flags': 0,
        'funcname': 'crc'
    }

    if len(argv) < 2 or '-h' in argv or '--help' in argv:
        return {
            'error': True,
            'error_description': USAGE % {'cmd': argv[0]}
        }

    idx = 1
    while idx < len(argv):
        arg = argv[idx]

        if arg.startswith('--tb='):
            res['table_bits'] = int(arg[len('--tb='):])
            if res['table_bits'] not in [2, 4, 8]:
                return {
                    'error': True,
                    'error_description': '--tb must be 2, 4 or 8!'
                }
        elif arg == '--ri':
            res['flags'] |= FLAG_REFIN
        elif arg == '--ro':
            res['flags'] |= FLAG_REFOUT
        elif arg.startswith('--iv='):
            val_str = arg[len('--iv='):]
            converted = False

            for base in [2, 10, 16]:
                try:
                    res['init_crc'] = int(val_str, base)
                    converted = True
                    break
                except ValueError:
                    pass

            if not converted:
                return {
                    'error': True,
                    'error_description': 'No valid value specified for --iv'
                }
        elif arg.startswith('--xoro='):
            val_str = arg[len('--xoro='):]
            converted = False

            for base in [2, 10, 16]:
                try:
                    res['xoro'] = int(val_str, base)
                    converted = True
                    break
                except ValueError:
                    pass

            if not converted:
                return {
                    'error': True,
                    'error_description': 'No valid value specified for --iv'
                }
        elif arg.startswith('--fn='):
            res['funcname'] = arg[len('--fn='):]
            if len(res['funcname']) == 0:
                return {
                    'error': True,
                    'error_description': 'Empty function name'
                }
            if re.search(r'[\s]', res['funcname']):
                return {
                    'error': True,
                    'error_description': 'Function name cannot contain whitespaces'
                }
        else:
            try:
                int(arg)
                break
            except ValueError:
                return {
                    'error': True,
                    'error_description': arg + ' is not a valid argument'
                }

        idx += 1

    for i in range(idx, len(argv)):
        try:
            val = int(argv[i])
            idx += 1
        except ValueError:
            break

        if val < 0:
            return {
                'error': True,
                'error_description': '%d is not a valid power, it must be positive' % val
            }

        res['powers'].append(val)

    if len(argv) - idx == 2:
        # read header file
        res['header_file'] = argv[idx]
        idx += 1

    if len(argv) - idx == 1:
        # read source file
        res['source_file'] = argv[idx]
        idx += 1
    else:
        return {
            'error': True,
            'error_description': 'Too many arguments' if len(argv) - idx > 1
                                 else 'Too few arguments'
        }

    res['powers'].sort()
    res['powers'].reverse()

    if len(res['powers']) == 0:
        return {
            'error': True,
            'error_description': 'No CRC polinomyal powers specified'
        }

    for power in res['powers'][1:]:
        res['generator'] |= 1 << power

    return res

def generate_lookuptable(table_bits, powers, flags):
    '''
    Con
    '''

    generator = 0
    test = 0x1 if flags & FLAG_REFIN else 1 << (powers[0] - 1)
    mask = (1 << powers[0]) - 1

    if flags & FLAG_REFIN:
        for power in powers[1:]:
            generator |= 1 << (powers[0] - 1 - power)
    else:
        for power in powers[1:]:
            generator |= 1 << power

    lookuptable = []
    for val in range(0, 2 ** table_bits):

        if flags & FLAG_REFIN:
            for _ in range(0, table_bits):
                if val & test:
                    val = ((val >> 1) ^ generator) & mask
                else:
                    val = (val >> 1) & mask
        else:
            val = val << (powers[0] - table_bits)

            for _ in range(0, table_bits):
                if val & test:
                    val = ((val << 1) ^ generator) & mask
                else:
                    val = (val << 1) & mask

        lookuptable.append(val)

    return lookuptable

def get_crc_type(crc_size):
    '''
    Return the smallest c type that will contain the crc
    Uses the stdint.h defines
    '''

    if crc_size > 32:
        return 'uint64_t'
    elif crc_size > 16:
        return 'uint32_t'
    elif crc_size > 8:
        return 'uint16_t'
    else:
        return 'uint8_t'

def generate_header(crc_size, funcname):
    '''
    Generates the header file for the crc function
    Returns a string
    '''

    return \
'''#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

%s %s(const uint8_t *buffer, size_t count);

#ifdef __cplusplus
} /* extern "C" */
#endif''' % (get_crc_type(crc_size), funcname)

def generate_source(**kwargs):
    '''
    Generates the source file (.c file) for the crc function
    Returns a dictionary containing:
        'error': True if an error occured
        'error_description': description of the error
        'content': string containing the source code
    '''

    if 'powers' not in kwargs:
        return {
            'error': True,
            'error_description': 'Must specify the powers list!'
        }

    table_bits = kwargs.get('table_bits', 8)
    powers = kwargs['powers']
    flags = kwargs.get('flags', 0)
    init_crc = kwargs.get('init_crc', 0)
    funcname = kwargs.get('funcname', 'crc')
    xoro = kwargs.get('xoro', 0)

    lookuptable = generate_lookuptable(table_bits, powers, flags)
    lookuptable_str = ['0x%0*x' % (powers[0] // 4, v) for v in lookuptable]

    include = ''
    params = {
        'type': get_crc_type(powers[0]),
        'funcname': funcname,
        'polynomial': '',
        'generator': '',
        'table_size': 2 ** table_bits,
        'table_bits': table_bits,
        'table_contents': '',
        'computation': '',
        'init_crc': init_crc,
        'ri': str(bool(flags & FLAG_REFIN)),
        'ro': str(bool(flags & FLAG_REFOUT)),
        'reflect_out': '',
        'xoro_code': '',
        'xoro': xoro
    }

    params['polynomial'] = ' + '.join(['x^%d' % p if p > 0 else '1' for p in powers])
    params['generator'] = 0
    for power in powers[1:]:
        params['generator'] |= 1 << power

    params['table_contents'] = ',\n\t\t'.join(
        [', '.join(line) for line in  zip(*[iter(lookuptable_str)]*4)]
    )

    if flags & FLAG_REFIN:
        if table_bits == 8:
            params['computation'] = 'r = (r >> 8) ^ lt[((uint8_t)r ^ *buffer) & 0xff];'
        elif table_bits == 4:
            params['computation'] = 'r = (r >> 4) ^ lt[((uint8_t)r ^ *buffer) & 0xf];' + \
                '\n\t\tr = (r >> 4) ^ lt[((uint8_t)r ^ (*buffer >> 4)) & 0xf];'
        elif table_bits == 2:
            params['computation'] = 'r = (r >> 2) ^ lt[((uint8_t)r ^ *buffer) & 0x3];' + \
                '\n\t\tr = (r >> 2) ^ lt[((uint8_t)r ^ (*buffer >> 2)) & 0x3];' + \
                '\n\t\tr = (r >> 2) ^ lt[((uint8_t)r ^ (*buffer >> 4)) & 0x3];' + \
                '\n\t\tr = (r >> 2) ^ lt[((uint8_t)r ^ (*buffer >> 6)) & 0x3];'
    else:
        if table_bits == 8:
            params['computation'] = \
                'r = (r << 8) ^ lt[((uint8_t)(r >> %(rs)d) ^ *buffer) & 0xff];'
        elif table_bits == 4:
            params['computation'] = \
                'r = (r << 4) ^ lt[((uint8_t)(r >> %(rs)d) ^ (*buffer >> 4)) & 0xf];' + \
                '\n\t\tr = (r << 4) ^ lt[((uint8_t)(r >> %(rs)d) ^ *buffer) & 0xf];'
        elif table_bits == 2:
            params['computation'] = \
                'r = (r << 2) ^ lt[((uint8_t)(r >> %(rs)d) ^ (*buffer >> 6)) & 0x3];' + \
                '\n\t\tr = (r << 2) ^ lt[((uint8_t)(r >> %(rs)d) ^ (*buffer >> 4)) & 0x3];' + \
                '\n\t\tr = (r << 2) ^ lt[((uint8_t)(r >> %(rs)d) ^ (*buffer >> 2)) & 0x3];' + \
                '\n\t\tr = (r << 2) ^ lt[((uint8_t)(r >> %(rs)d) ^ *buffer) & 0x3];'

        params['computation'] = params['computation'] % {'rs' : powers[0] - table_bits}

    if flags & FLAG_REFOUT:
        if powers[0] > 32:
            params['reflect_out'] = '\n\tr = (r >> 32) | ((r & 0xffffffff) << 32);\n' + \
                '\tr = ((r & 0xffff0000ffff0000) >> 16) | ((r & 0x0000ffff0000ffff) << 16);\n' + \
                '\tr = ((r & 0xff00ff00ff00ff00) >>  8) | ((r & 0x00ff00ff00ff00ff) <<  8);\n'
        elif powers[0] > 16:
            params['reflect_out'] = '\n\tr = (r >> 16) | ((r & 0xffff) << 16);\n' + \
                '\tr = ((r & 0xff00ff00) >>  8) | ((r & 0x00ff00ff) <<  8);\n'
        elif powers[0] > 8:
            params['reflect_out'] = '\n\tr = (r >> 8) | ((r & 0xff) << 8);\n'

    if xoro != 0:
        params['xoro_code'] = '\n\tr ^= 0x%x;\n' % xoro

    if 'header_file' in kwargs:
        include = '#include "%s"\n\n' % kwargs['header_file']

    return {
        'error': False,
        'content': include + '''%(type)s %(funcname)s(const uint8_t *buffer, size_t count) {
    // %(polynomial)s
    // reflected input: %(ri)s
    // reflected output: %(ro)s
    // init crc: 0x%(init_crc)x
    // xor out: 0x%(xoro)x

    static const %(type)s lt[%(table_size)s] = {
        %(table_contents)s
    };
    %(type)s r = 0x%(init_crc)x;

    while (count > 0) {
        %(computation)s
        buffer++;
        count--;
    }
%(reflect_out)s%(xoro_code)s
    return r;
}''' % params
    }

def main():
    '''
    Parses cmdline, and generates files
    Prints errors and stats to stdout
    '''

    res = parse_cmdline(sys.argv)
    if res['error']:
        print ('Error: ' + res['error_description'])
        exit(1)

    print ('Table bits = %d' % res['table_bits'])
    print ('Powers = %s' % str(res['powers']))
    print ('Generator = 0x%04x' % res['generator'])

    if res['header_file']:
        print ('Header file = %s' % res['header_file'])

    print ('Source file = %s' % res['source_file'])

    if res['header_file']:
        print ('Generating %s' % res['header_file'])
        headerfd = open(res['header_file'], 'w')
        headerfd.write(generate_header(res['powers'][0], res['funcname']))
        headerfd.close()

    print ('Generating %s' % res['source_file'])
    resg = generate_source(**res)
    if resg['error']:
        print ('Error: ' + resg['error_description'])
        exit(1)

    sourcefd = open(res['source_file'], 'w')
    sourcefd.write(resg['content'])
    sourcefd.close()

    print ('Done')

if __name__ == '__main__':
    main()
