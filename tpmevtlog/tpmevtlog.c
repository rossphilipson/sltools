/*
 * tpmevtlog.c: Routines to print out TPM 1.2/2.0 event logs
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "tpmevtlog.h"
#include "evttypes.h"

/*static int fd;

static inline int tpm_log_event(uint32_t event_size, void *event)
{
	ssize_t ret;

	ret = write(fd, event, event_size);
	if (ret == -1) {
		printf("Failed to write event to log\n");
		return -1;
	}

	return 0;
}

static void sl_tpm12_log_event(uint32_t pcr, uint8_t *digest,
			       const uint8_t *event_data, uint32_t event_size)
{
	struct tpm12_pcr_event *pcr_event;
	uint32_t total_size;
	uint8_t log_buf[SL_TPM12_LOG_SIZE];

	memset(log_buf, 0, SL_TPM12_LOG_SIZE);
	pcr_event = (struct tpm12_pcr_event *)log_buf;
	pcr_event->pcr_index = pcr;
	pcr_event->type = TXT_EVTYPE_SLAUNCH;
	memcpy(&pcr_event->digest[0], digest, SHA1_DIGEST_SIZE);
	pcr_event->size = event_size;
	memcpy((uint8_t *)pcr_event + sizeof(struct tpm12_pcr_event),
	       event_data, event_size);

	total_size = sizeof(struct tpm12_pcr_event) + event_size;

	if (tpm_log_event(total_size, pcr_event))
		printf("Failed to write TPM 1.2 event\n");
}

static void sl_tpm20_log_event(uint32_t pcr, uint8_t *digest, uint16_t algo,
			       const uint8_t *event_data, uint32_t event_size)
{
	struct tpm20_pcr_event_head *head;
	struct tpm20_digest_values *dvs;
	struct tpm20_ha *ha;
	struct tpm20_pcr_event_tail *tail;
	uint8_t *dptr;
	uint32_t total_size;
	uint8_t log_buf[SL_TPM20_LOG_SIZE];

	memset(log_buf, 0, SL_TPM20_LOG_SIZE);
	head = (struct tpm20_pcr_event_head *)log_buf;
	head->pcr_index = pcr;
	head->event_type = TXT_EVTYPE_SLAUNCH;
	dvs = (struct tpm20_digest_values *)
		((uint8_t *)head + sizeof(struct tpm20_pcr_event_head));
	dvs->count = 1;
	ha = (struct tpm20_ha *)
		((uint8_t *)dvs + sizeof(struct tpm20_digest_values));
	ha->algorithm_id = algo;
	dptr = (uint8_t *)ha + sizeof(struct tpm20_ha);

	switch (algo) {
	case TPM_HASH_ALG_SHA512:
		memcpy(dptr, digest, SHA512_DIGEST_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA512_DIGEST_SIZE);
		break;
	case TPM_HASH_ALG_SHA256:
		memcpy(dptr, digest, SHA256_DIGEST_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA256_DIGEST_SIZE);
		break;
	case TPM_HASH_ALG_SHA1:
	default:
		memcpy(dptr, digest, SHA1_DIGEST_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA1_DIGEST_SIZE);
	};

	tail->event_size = event_size;
	memcpy((uint8_t *)tail + sizeof(struct tpm20_pcr_event_tail),
	       event_data, event_size);

	total_size = (uint32_t)((uint8_t *)tail - (uint8_t *)head) +
		sizeof(struct tpm20_pcr_event_tail) + event_size;

	if (tpm_log_event(total_size, &log_buf[0]))
		printf("Failed to write TPM 2.0 event\n");
}

void log_event(int is_tpm20)
{
	uint8_t digest[20];
	void *p = (void *)tpm_log_event;

	memcpy(&digest[0], p, 20);

	fd = open("/sys/kernel/security/slaunch/eventlog", O_WRONLY);
	if (fd == -1) {
		printf("Failed to open slaunch/eventlog node\n");
		return;
	}

	if (is_tpm20)
		sl_tpm20_log_event(23, &digest[0], TPM_HASH_ALG_SHA1,
				   "Test event 20", strlen("Test event 20"));
	else
		sl_tpm12_log_event(23, &digest[0],
				   "Test event 12", strlen("Test event 12"));

	close(fd);
}
*/

void usage(void)
{
	printf("Usage: tpmevtlog <evtlog-file>\n");
}

int main(int argc, char *argv[])
{
	if (argc <= 1) {
		usage();
		return 0;
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage();
		return 0;
	}

	printf("GOT: %s\n", argv[1]);
	print_evttype(0x404);

	return 0;
}
