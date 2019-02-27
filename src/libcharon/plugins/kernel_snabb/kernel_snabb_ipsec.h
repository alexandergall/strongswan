/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */


#ifndef KERNEL_SNABB_IPSEC_H_
#define KERNEL_SNABB_IPSEC_H_

#include <kernel/kernel_ipsec.h>

/**
 * Layout of the memory region shared with the Snabb
 * pseudo-kernel
 */
struct snabb_ipsec_sa {
    uint32_t spi;
    uint64_t tstamp;
    uint32_t replay_window;
    uint16_t enc_alg;
    union {
        struct {
            uint8_t  key[16];
            uint8_t  salt[4];
        } aes_gcm_icv16;
    } enc_key;
} __attribute__ ((__packed__)) ;

/**
 * Create an instance of kernel_ipsec_t
 *
 * @return		created object
 */
kernel_ipsec_t *kernel_snabb_ipsec_create();

/**
 * Enumerate the installed SAs
 *
 * @return		enumerator over (ike_sa_t*, uint32_t)
 */
enumerator_t *kernel_snabb_ipsec_create_sa_enumerator();

#endif /** KERNEL_SNABB_IPSEC_H_ @}*/
