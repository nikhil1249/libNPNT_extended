/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <defines.h>
#include <control_iface.h>

uint8_t* base64_encode(const uint8_t *src, uint16_t len, uint16_t *out_len);

uint8_t* base64_decode(const uint8_t *src, uint16_t len, uint16_t *out_len);


#ifdef __cplusplus
}
#endif
