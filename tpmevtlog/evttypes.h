/*
 * evttypes.h: TPM 1.2/2.0 event types
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

#ifndef __EVTTYPES_H__
#define __EVTTYPES_H__

/* TCG specification: Legacy BIOS types */
enum BIOS_EVTTYPES {
	EV_PREBOOT_CERT		= 0X0,
	EV_POST_CODE		= 0x1,
	EV_UNUSED		= 0x2,
	EV_NO_ACTION		= 0x3,
	EV_SEPARATOR		= 0x4,
	EV_ACTION		= 0x5,
	EV_EVENT_TAG		= 0x6,
	EV_SCRTM_CONTENTS	= 0x7,
	EV_SCRTM_VERSION	= 0x8,
	EV_CP_UMICROCODE	= 0x9,
	EV_PLATFORM_CONFIG_FLAGS = 0xa,
	EV_TABLE_OF_SERVICES	= 0xb,
	EV_COMPACT_HASH		= 0xc,
	EV_IPL			= 0xd,
	EV_IPL_PARTITION_DATA	= 0xe,
	EV_NON_HOST_CODE	= 0xf,
	EV_NON_HOST_CONFIG	= 0x10,
	EV_NON_HOST_INFO	= 0x11,
	EV_OMIT_BOOT_DEVICE_EVENTS = 0x12
};

/* TCG specification: EFI Firmware types */
enum EFI_EVTTYPES {
	EV_EFI_EVENT_BASE		= 0x80000000,
	EV_EFI_VARIABLE_DRIVER_CONFIG	= 0x80000001,
	EV_EFI_VARIABLE_BOOT		= 0x80000002,
	EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003,
	EV_EFI_BOOT_SERVICES_DRIVER	= 0x80000004,
	EV_EFI_RUN_TIMESERVICE_SDRIVER	= 0x80000005,
	EV_EFI_GPT_EVENT		= 0x80000006,
	EV_EFI_ACTION			= 0x80000007,
	EV_EFI_PLATFORM_FIRMWARE_BLOB	= 0x80000008,
	EV_EFI_HANDOFF_TABLES		= 0x80000009,
	EV_EFI_HCRTM_EVENT		= 0x80000010,
	EV_EFI_VARIABLE_AUTHORITY	= 0x800000E0
};

/* TXT specification: DRTM types */
enum TXT_EVTTYPES {
	EV_TXT_BASE			= 0x400,
	EV_TXT_PCR_MAPPING		= 0x401,
	EV_TXT_HASH_START		= 0x402,
	EV_TXT_COMBINED_HASH		= 0x403,
	EV_TXT_MLE_HASH			= 0x404,
	EV_TXT_BIOS_AC_REG_DATA		= 0x40a,
	EV_TXT_CPU_SCRTM_STAT		= 0x40b,
	EV_TXT_LCP_CONTROL_HASH		= 0x40c,
	EV_TXT_ELEMENTS_HASH		= 0x40d,
	EV_TXT_STM_HASH			= 0x40e,
	EV_TXT_OS_SINIT_DATA_CAP_HASH	= 0x40f,
	EV_TXT_SINIT_PUBKEY_HASH	= 0x410,
	EV_TXT_LCP_HASH			= 0x411,
	EV_TXT_LCP_DETAILS_HASH		= 0x412,
	EV_TXT_LCP_AUTHORITIES_HASH	= 0x413,
	EV_TXT_NV_INFO_HASH		= 0x414,
	EV_TXT_COLD_BOOT_BIOS_HASH	= 0x415,
	EV_TXT_KM_HASH			= 0x416,
	EV_TXT_BPM_HASH			= 0x417,
	EV_TXT_KM_INFO_HASH		= 0x418,
	EV_TXT_BPM_INFO_HASH		= 0x419,
	EV_TXT_BOOTPOL_HASH		= 0x41a,
	EV_TXT_RAND_VALUE		= 0x4fe,
	EV_TXT_CAP_VALUE		= 0xff
};

#define CASE(e) case (e): \
			printf("Event Type: " #e "\n"); \
			break;

static void print_evttype(uint32_t evttype)
{
	switch (evttype) {
	CASE(EV_PREBOOT_CERT)
	CASE(EV_POST_CODE)
	CASE(EV_UNUSED)
	CASE(EV_NO_ACTION)
	CASE(EV_SEPARATOR)
	CASE(EV_ACTION)
	CASE(EV_EVENT_TAG)
	CASE(EV_SCRTM_CONTENTS)
	CASE(EV_SCRTM_VERSION)
	CASE(EV_CP_UMICROCODE)
	CASE(EV_PLATFORM_CONFIG_FLAGS)
	CASE(EV_TABLE_OF_SERVICES)
	CASE(EV_COMPACT_HASH)
	CASE(EV_IPL)
	CASE(EV_IPL_PARTITION_DATA)
	CASE(EV_NON_HOST_CODE)
	CASE(EV_NON_HOST_CONFIG)
	CASE(EV_NON_HOST_INFO)
	CASE(EV_OMIT_BOOT_DEVICE_EVENTS)
	CASE(EV_EFI_EVENT_BASE)
	CASE(EV_EFI_VARIABLE_DRIVER_CONFIG)
	CASE(EV_EFI_VARIABLE_BOOT)
	CASE(EV_EFI_BOOT_SERVICES_APPLICATION)
	CASE(EV_EFI_BOOT_SERVICES_DRIVER)
	CASE(EV_EFI_RUN_TIMESERVICE_SDRIVER)
	CASE(EV_EFI_GPT_EVENT)
	CASE(EV_EFI_ACTION)
	CASE(EV_EFI_PLATFORM_FIRMWARE_BLOB)
	CASE(EV_EFI_HANDOFF_TABLES)
	CASE(EV_EFI_HCRTM_EVENT)
	CASE(EV_EFI_VARIABLE_AUTHORITY)
	CASE(EV_TXT_BASE)
	CASE(EV_TXT_PCR_MAPPING)
	CASE(EV_TXT_HASH_START)
	CASE(EV_TXT_COMBINED_HASH)
	CASE(EV_TXT_MLE_HASH)
	CASE(EV_TXT_BIOS_AC_REG_DATA)
	CASE(EV_TXT_CPU_SCRTM_STAT)
	CASE(EV_TXT_LCP_CONTROL_HASH)
	CASE(EV_TXT_ELEMENTS_HASH)
	CASE(EV_TXT_STM_HASH)
	CASE(EV_TXT_OS_SINIT_DATA_CAP_HASH)
	CASE(EV_TXT_SINIT_PUBKEY_HASH)
	CASE(EV_TXT_LCP_HASH)
	CASE(EV_TXT_LCP_DETAILS_HASH)
	CASE(EV_TXT_LCP_AUTHORITIES_HASH)
	CASE(EV_TXT_NV_INFO_HASH)
	CASE(EV_TXT_COLD_BOOT_BIOS_HASH)
	CASE(EV_TXT_KM_HASH)
	CASE(EV_TXT_BPM_HASH)
	CASE(EV_TXT_KM_INFO_HASH)
	CASE(EV_TXT_BPM_INFO_HASH)
	CASE(EV_TXT_BOOTPOL_HASH)
	CASE(EV_TXT_RAND_VALUE)
	CASE(EV_TXT_CAP_VALUE)
	default:
		printf("Event Type: UNKNOWN(0x%x)\n", evttype);
		break;
	};
}

#endif /* __EVTTYPES_H__ */
