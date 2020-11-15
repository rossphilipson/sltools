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
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tpmevtlog.h"
#include "evttypes.h"

static int tpm12_print_evtlog(uint8_t *buffer, uint32_t length)
{
	struct tpm12_event_log_header *evtlog =
			(struct tpm12_event_log_header *)buffer;
	struct tpm12_pcr_event *pcr_event;

	if (length < sizeof(struct tpm12_event_log_header)) {
		printf("File too small to be a TPM 1.2 event log\n");
		return 1;
	}

	printf("TPM 1.2 Event Log:\n");
	printf("Signature:               %s\n", evtlog->signature);
	printf("Container Version Major: 0x%2.2x\n", evtlog->container_ver_major);
	printf("Container Version Minor: 0x%2.2x\n", evtlog->container_ver_minor);
	printf("PCR Event Version Major: 0x%2.2x\n", evtlog->pcr_event_ver_major);
	printf("PCR Event Version Minor: 0x%2.2x\n", evtlog->pcr_event_ver_minor);
	printf("Container Size:          0x%x\n", evtlog->container_size);
	printf("PCR Events Offset:       0x%x\n", evtlog->pcr_events_offset);
	printf("Next Event Offset:       0x%x\n", evtlog->next_event_offset);

	if ((length == sizeof(struct tpm12_event_log_header)) ||
	    (evtlog->pcr_events_offset == evtlog->next_event_offset)) {
		printf("TPM 1.2 event log empty of events\n");
		return 0;
	}

	if (length < (sizeof(struct tpm12_event_log_header) +
	    evtlog->pcr_events_offset)) {
		printf("TPM 1.2 malformed\n");
		return 1;
	}

	return 0;
}

static int tpm20_print_evtlog(uint8_t *buffer, uint32_t length)
{
	print_evttype(0x404);
	print_evttype(0x504);

	return 0;
}

static void usage(void)
{
	printf("Usage: tpmevtlog <evtlog-file>\n");
}

int main(int argc, char *argv[])
{
	FILE *f;
	struct stat s;
	uint8_t *b;
	size_t n;
	int r = 0;

	if (argc <= 1) {
		usage();
		return 1;
	}

	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage();
		return 1;
	}

	f = fopen(argv[1], "r");
	if (!f) {
		printf("Failed to open file: %s error: %d\n",
		       argv[1], errno);
		return 1;
	}

	if (stat(argv[1], &s)) {
		printf("Failed to stat file: %s error: %d\n",
		       argv[1], errno);
		return 1;
	}

	b = malloc(s.st_size);
	if (!b) {
		printf("Failed to alloc buffer error: %d\n", errno);
		return 1;
	}

	n = fread(b, 1, s.st_size, f);
	if (n != s.st_size) {
		printf("Failed to read file: %sd\n", argv[1]);
		return 1;
	}

	fclose(f);

	if (n < (sizeof(struct tpm12_pcr_event) + 20)) {
		printf("File too small to be a TPM event log\n");
		r = 1;
		goto out;
	}

	if (!strcmp((const char *)b, TPM12_EVTLOG_SIGNATURE))
		r = tpm12_print_evtlog(b, n);
	else
		r = tpm20_print_evtlog(b, n);

out:
	free(b);

	return r;
}
