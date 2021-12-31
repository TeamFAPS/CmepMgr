
#ifndef _PSP2_KERNEL_SBL_US_H_
#define _PSP2_KERNEL_SBL_US_H_

#define SCE_SBL_SM_COMM_FID_SM_ENCIND_SLSK (0x50002)

typedef struct SceSblSmUpdateEntryList {
	uint32_t unused_0[2];
	uint32_t use_lv2_mode_0; // if 1, use lv2 list
	uint32_t use_lv2_mode_1; // if 1, use lv2 list
	uint32_t unused_10[3];
	uint32_t list_count;     // must be < 0x1F1
	uint32_t unused_20[4];
	uint32_t total_count;    // only used in LV1 mode
	uint32_t unused_34[1];
	union {
		SceKernelAddrPair lv1[0x1F1];
		SceKernelAddrPair lv2[0x1F1];
	} list;
} SceSblSmUpdateEntryList;

typedef struct heap_hdr {
	void *data;
	uint32_t size;
	uint32_t size_aligned;
	uint32_t padding;
	struct heap_hdr *prev;
	struct heap_hdr *next;
} __attribute__((packed)) heap_hdr_t;

typedef struct SceUsCmdD0002_t {
	int mode;
	int unk_4;
	int unk_8[0xA];
	char unk_30[0x28];
} SceUsCmdD0002_t;

#endif /* _PSP2_KERNEL_SBL_US_H_ */
