/*
 * tpmevtlog.h: Definitions for TPM 1.2/2.0 event logs
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TPMEVTLOG_H__
#define __TPMEVTLOG_H__

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define SHA1_DIGEST_SIZE        20
#define SHA256_DIGEST_SIZE      32
#define SHA512_DIGEST_SIZE      64

#define TPM_HASH_ALG_SHA1    (uint16_t)(0x0004)
#define TPM_HASH_ALG_SHA256  (uint16_t)(0x000B)
#define TPM_HASH_ALG_SHA512  (uint16_t)(0x000D)

/*
 * TPM event log structures defined in both the TXT specification and
 * the TCG documentation.
 */
#define TPM12_EVTLOG_SIGNATURE "TXT Event Container"

struct tpm12_event_log_header {
	char		signature[20];
	char		reserved[12];
	uint8_t		container_ver_major;
	uint8_t		container_ver_minor;
	uint8_t		pcr_event_ver_major;
	uint8_t		pcr_event_ver_minor;
	uint32_t	container_size;
	uint32_t	pcr_events_offset;
	uint32_t	next_event_offset;
	/* PCREvents[] */
} __packed;

struct tpm12_pcr_event {
	uint32_t	pcr_index;
	uint32_t	type;
	uint8_t		digest[20];
	uint32_t	size;
	/* Data[] */
} __packed;

#define TPM20_EVTLOG_SIGNATURE "Spec ID Event03"

struct tpm20_event_algo_size {
	uint16_t	algorithm_id;
	uint16_t	digest_size;
} __packed;

struct tpm20_spec_id_event_struct {
	uint8_t		signature[16];
	uint32_t	platform_class;
	uint8_t		spec_version_minor;
	uint8_t		spec_version_major;
	uint8_t		spec_errata;
	uint8_t		uintn_size;
	/* uint32_t number_algorithms */
	/* EventAlgorithmSize[number_algorithms]; */
	/* uint8_t vendor_info_size */
	/* VendorInfo[vendor_info_size] */
} __packed;

struct tpm20_ha {
	uint16_t	algorithm_id;
	/* digest[AlgorithmID_DIGEST_SIZE] */
} __packed;

struct tpm20_digest_values {
	uint32_t	count;
	/* TPMT_HA digests[count] */
} __packed;

struct tpm20_pcr_event_head {
	uint32_t	pcr_index;
	uint32_t	event_type;
} __packed;

/* Variable size array of hashes in the tpm20_digest_values structure */

struct tpm20_pcr_event_tail {
	uint32_t	event_size;
	/* Event[EventSize]; */
} __packed;

#define SL_MAX_EVENT_DATA	64
#define SL_TPM12_LOG_SIZE	(sizeof(struct tpm12_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM20_LOG_SIZE	(sizeof(struct tpm20_ha) + \
				SHA512_DIGEST_SIZE + \
				sizeof(struct tpm20_digest_values) + \
				sizeof(struct tpm20_pcr_event_head) + \
				sizeof(struct tpm20_pcr_event_tail) + \
				SL_MAX_EVENT_DATA)

#endif /* __TPMEVTLOG_H__ */
