/*
 * CmepMgr
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sm_comm.h>
#include <psp2kern/kernel/iofilemgr.h>
#include <psp2kern/sblacmgr.h>
#include <psp2kern/io/fcntl.h>
#include "cmep_mgr.h"
#include "cmep_mgr_internal.h"
#include "update_service.h"


const SceSelfAuthInfo update_sm = {
	.program_authority_id = 0x2808000000000001,
	.padding = {0, 0, 0, 0, 0, 0, 0, 0},
	.capability = {
		0x80, 0x00, 0x00, 0x00, 0xC0, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	.attribute = {
		0x80, 0x09, 0x80, 0x03, 0x00, 0x00, 0xC3, 0x00, 0x00, 0x00, 0x80, 0x09, 0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
	},
	.secret = {
		.shared_secret_0 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.klicensee       = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.shared_secret_2 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.shared_secret_3_0 = 0,
		.shared_secret_3_1 = 0,
		.shared_secret_3_2 = 0,
		.shared_secret_3_3 = 0
	}
};

#define CMEP_MGR_ARGS_SIZE (0x1000)

SceSblSmCommId update_sm_id;

SceUID cmep_stage1_base_uid;
void  *cmep_stage1_base;

SceUID cmep_stage2_base_uid;
void  *cmep_stage2_base;

SceUID cmep_args_uid;
void  *cmep_args_base;

SceUID mtx_lock;
SceUID global_sema;

SceKernelAddrPair  payload_paddr[0x20] __attribute__((aligned(0x40)));
SceKernelPaddrList payload_paddr_list __attribute__((aligned(0x40)));

int start_sm_update(void){

	int res;
	SceAuthInfo auth_info;

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s in <-\n", __FUNCTION__);
#endif


#if CMEP_MGR_DBG_LOG != 0
	SceKernelThreadInfo info;
	memset(&info, 0, sizeof(info));
	info.size = sizeof(info);

	ksceKernelGetThreadInfo(ksceKernelGetThreadId(), &info);

	ksceDebugPrintf("Stack base : %p\n", info.stack);
	ksceDebugPrintf("Stack size : 0x%08X\n", info.stackSize);
	ksceDebugPrintf("Current stack point : %p\n", &auth_info);
#endif

	int perm;

	perm = ksceKernelSetPermission(0x80);

	memset(&auth_info, 0, sizeof(auth_info));
	memcpy(&auth_info.request, &update_sm, sizeof(update_sm));

	res = ksceSblACMgrGetMediaType("os0:sm/update_service_sm.self", &(auth_info.media_type));
	if(res != 0){
#if CMEP_MGR_DBG_LOG != 0
		ksceDebugPrintf("%s sceSblACMgrGetMediaType failed : 0x%X\n", __FUNCTION__, res);
#endif
		goto error;
	}

	auth_info.self_type = (auth_info.self_type & ~0xF) | 2;	

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s loading update_service_sm...\n", __FUNCTION__);
#endif

	res = ksceSblSmCommStartSmFromFile(0, "os0:sm/update_service_sm.self", 0, &auth_info, &update_sm_id);

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s out ->\n", __FUNCTION__);
#endif

error:
	ksceKernelSetPermission(perm);
	return res;
}

int stop_sm_update(void){

	SceSblSmCommPair sm_res;

	return ksceSblSmCommStopSm(update_sm_id, &sm_res);
}

int corrupt_word(uintptr_t PA){

	int res = 0, resp = 0;

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s %p\n", __FUNCTION__, PA);
#endif

	void *ptr = ksceKernelAllocHeapMemory(0x1000B, sizeof(SceSblSmUpdateEntryList) + 0x3F);
	if(ptr == NULL)
		return -1;

	SceSblSmUpdateEntryList *pUpdateList = (SceSblSmUpdateEntryList *)((((uintptr_t)ptr) + 0x3F) & ~0x3F);

	memset(pUpdateList, 0, sizeof(*pUpdateList));

	pUpdateList->use_lv2_mode_0     = 0;
	pUpdateList->use_lv2_mode_1     = 0;
	pUpdateList->list_count         = 3;
	pUpdateList->total_count        = 1;
	pUpdateList->list.lv1[0].addr   = 0x50000000;
	pUpdateList->list.lv1[0].length = 0x10;
	pUpdateList->list.lv1[1].addr   = 0x50000000;
	pUpdateList->list.lv1[1].length = 0x10;
	pUpdateList->list.lv1[2].addr   = 0;
	pUpdateList->list.lv1[2].length = PA - offsetof(heap_hdr_t, next);

	res = ksceSblSmCommCallFunc(update_sm_id, SCE_SBL_SM_COMM_FID_SM_ENCIND_SLSK, &resp, pUpdateList, sizeof(*pUpdateList));
	if(res >= 0 && resp != 0x800F0216)
		res = resp;

	ksceKernelFreeHeapMemory(0x1000B, ptr);

	return res;
}

int corrupt_nwords(const unsigned int *addr_list, SceSize list_num){

	int res = 0;

	for(SceSize i=0;i<list_num;i++){
		res = corrupt_word(addr_list[i]);
		if(res < 0)
			break;
	}

	return res;
}

const unsigned int list_0xD0002_corrupt_addr[] = {
	0x4BD10,
	0x4BD14,
	0x4BD18,
	0x4BD1C,
	0x4BD20
};

const unsigned int list_0xD0002_corrupt_addr_371[] = {
	0x4BD74,
	0x4BD78,
	0x4BD7C,
	0x4BD80,
	0x4BD84
};

int cmepMgrOpen(void){

	int res;

	res = start_sm_update();
	if(res >= 0){
		SceKblParam *pKblParam = (SceKblParam *)ksceKernelSysrootGetKblParam();
		if(pKblParam->current_fw_version >= 0x3000000 && pKblParam->current_fw_version < 0x3710000){
			res = corrupt_nwords(list_0xD0002_corrupt_addr, 5);
			ksceDebugPrintf("corrupt_nwords for 360\n");
		}else if(pKblParam->current_fw_version >= 0x3710000 && pKblParam->current_fw_version < 0x3740000){
			res = corrupt_nwords(list_0xD0002_corrupt_addr_371, 5);
			ksceDebugPrintf("corrupt_nwords for 371\n");
		}else{
			SCE_KERNEL_PANIC();
		}
	}

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s 0x%X\n", __FUNCTION__, res);
#endif

	return res;
}

int cmepMgrClose(void){

	int res;

	res = stop_sm_update();

	return res;
}

void cmepMgrDcacheCleanRange(const void *ptr, SceSize size){
	ksceKernelCpuDcacheAndL2WritebackRange((void *)(((uintptr_t)ptr) & ~0x3F), (size + (((uintptr_t)ptr) & 0x3F) + 0x3F) & ~0x3F);
}

void cmepMgrDcacheInvalidateRange(const void *ptr, SceSize size){
	ksceKernelCpuDcacheAndL2InvalidateRange((void *)(((uintptr_t)ptr) & ~0x3F), (size + (((uintptr_t)ptr) & 0x3F) + 0x3F) & ~0x3F);
}

int _cmepMgrCallFunc(int cmd, void *argp, SceSize argp_length){

	int res, resp;
	SceUsCmdD0002_t cmd_arg;

	if(argp_length > CMEP_MGR_ARGS_SIZE)
		return -1;

	memset(&cmd_arg, 0, sizeof(cmd_arg));
	memcpy(cmep_args_base, argp, argp_length);

	ksceKernelGetPaddr(cmep_stage1_base, (uintptr_t *)&cmd_arg.mode);
	ksceKernelGetPaddr(cmep_args_base, (uintptr_t *)&cmd_arg.unk_4);
	cmd_arg.unk_8[0] = cmd;

	SceKblParam *pKblParam = (SceKblParam *)ksceKernelSysrootGetKblParam();
	if(pKblParam->current_fw_version >= 0x3710000 && pKblParam->current_fw_version < 0x3740000){
		cmd_arg.unk_8[1] = cmd_arg.mode;
		ksceKernelGetPaddr(&(cmd_arg.unk_8[1]), (uintptr_t *)&cmd_arg.mode);
	}

	cmepMgrDcacheCleanRange(&cmd_arg, sizeof(cmd_arg));
	cmepMgrDcacheCleanRange(cmep_args_base, CMEP_MGR_ARGS_SIZE);

	res = ksceSblSmCommCallFunc(update_sm_id, 0xD0002, &resp, &cmd_arg, sizeof(cmd_arg));
	if(res == 0)
		res = resp;

	cmepMgrDcacheInvalidateRange(cmep_args_base, CMEP_MGR_ARGS_SIZE);

	memcpy(argp, cmep_args_base, argp_length);
	memset(cmep_args_base, 0, CMEP_MGR_ARGS_SIZE);

	return res;
}

// no-unroll-loop
__attribute__((optimize("O2")))
SceUInt32 bit_start_from_left(SceUInt32 value){

	SceInt32 val_inv;
	SceUInt32 res = 0,  mask = 3, tmp;

	for(int i=0;i<32;i+=2){
		val_inv = (~value >> (32 - (i + 2))) & mask;
		tmp = (val_inv & 1) + (val_inv >> 1);
		res += (tmp & (mask & ((val_inv << 0x1E) >> 0x1F)));
		mask = (1 << tmp) - 1;
	}

	return res;
}

const unsigned char cmep_stage1_payload[] = {
	0x21, 0xC0, 0x22, 0x11, // movh r0, 0x1122
	0x04, 0xC0, 0x44, 0x33, // or3  r0, 0x3344, low addr
	0x0F, 0x10,             // jsr  r0
	0x96, 0xD3, 0xBE, 0x80, // movu r3, 0x80BE96 (0xD0002 return)
	0x3E, 0x10              // jmp  r3
};

int cmepMgrSetStage2Address(void *base, uintptr_t PA){

	SceUIntPtr ret_point;

	memcpy(base, cmep_stage1_payload, sizeof(cmep_stage1_payload));

	SceKblParam *pKblParam = (SceKblParam *)ksceKernelSysrootGetKblParam();
	if(pKblParam->current_fw_version >= 0x3000000 && pKblParam->current_fw_version < 0x3710000){
		ret_point = 0x80BE96;
	}else if(pKblParam->current_fw_version >= 0x3710000 && pKblParam->current_fw_version < 0x3740000){
		ret_point = 0x80BEFC;
	}else{
		SCE_KERNEL_PANIC();
	}

	((char *)base)[10] = (char)(ret_point);
	((char *)base)[12] = (char)(ret_point >> 8);
	((char *)base)[13] = (char)(ret_point >> 16);

	((char *)base)[6] = (char)(PA);
	((char *)base)[7] = (char)(PA >> 8);
	((char *)base)[2] = (char)(PA >> 16);
	((char *)base)[3] = (char)(PA >> 24);

	return 0;
}

int cmepMgrUnload(void){

	if(cmep_stage2_base_uid < 0){
		return -1;
	}

	ksceKernelFreeMemBlock(cmep_stage2_base_uid);

	cmep_stage2_base_uid = -1;
	cmep_stage2_base     = NULL;

	return 0;
}

int cmepMgrLoad(const void *data, SceSize size){

	SceSize nonalign_size = size;

	int res;

	size = (size + 0xFFF) & ~0xFFF;

	if(size == 0 || cmep_stage2_base_uid >= 0)
		return -1;

	SceUInt32 align = bit_start_from_left(size);

	align = (1 << (32 - align)) - 1;

	size = (size + align) & (~align);


	cmep_stage2_base_uid = ksceKernelAllocMemBlock("CmepMgrStage2Base", 0x10208006, size, NULL);
	if(cmep_stage2_base_uid < 0)
		return cmep_stage2_base_uid;

	ksceKernelGetMemBlockBase(cmep_stage2_base_uid, &cmep_stage2_base);

	SceKernelAddrPair input;
	input.addr   = (uintptr_t)cmep_stage2_base;
	input.length = size;

	payload_paddr_list.size       = sizeof(payload_paddr_list);
	payload_paddr_list.list_size  = 0x20;
	payload_paddr_list.ret_length = 0;
	payload_paddr_list.ret_count  = 0;
	payload_paddr_list.list       = payload_paddr;

	ksceKernelGetPaddrList(&input, &payload_paddr_list);

	if(payload_paddr_list.ret_length != 1 || payload_paddr_list.ret_count != 1){
		res = -2;
		goto error;
	}
#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("Payload location %p 0x%08X\n", payload_paddr[0].addr, payload_paddr[0].length);
#endif
	cmepMgrSetStage2Address(cmep_stage1_base, payload_paddr[0].addr);

	memcpy(cmep_stage2_base, data, nonalign_size);
	res = 0;

#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s OK\n", __FUNCTION__);
#endif

end:
	return res;

error:
#if CMEP_MGR_DBG_LOG != 0
	ksceDebugPrintf("%s error(0x%X)\n", __FUNCTION__, res);
#endif

	cmepMgrUnload();
	goto end;
}

int cmepMgrLoadByPath(const char *path){

	int res;
	SceUID fd, memid;
	void *cmep_stage2_base_temp;

	fd = ksceIoOpen(path, SCE_O_RDONLY, 0);
	if(fd < 0)
		return fd;

	SceIoStat stat;

	res = ksceIoGetstatByFd(fd, &stat);
	if(res < 0)
		goto io_close;

	memid = ksceKernelAllocMemBlock("CmepMgrStage2BaseTemp", 0x1020D006, (stat.st_size + 0xFFF) & ~0xFFF, NULL);
	if(memid < 0){
		res = memid;
		goto io_close;
	}

	res = ksceKernelGetMemBlockBase(memid, &cmep_stage2_base_temp);
	if(res < 0)
		goto free_memblk;

	res = ksceIoRead(fd, cmep_stage2_base_temp, stat.st_size);
	if(res < 0)
		goto free_memblk;

	if(res != stat.st_size){
		res = 0x8002A000;
		goto free_memblk;
	}

	res = cmepMgrLoad(cmep_stage2_base_temp, stat.st_size);

free_memblk:
	ksceKernelFreeMemBlock(memid);

io_close:
	ksceIoClose(fd);

	return res;
}

int _cmepMgrStart(const void *data, SceSize size){

	int res;

	res = cmepMgrLoad(data, size);
	if(res < 0)
		return res;

	res = cmepMgrOpen();
	if(res < 0){
		return res;
	}

	return res;
}

int _cmepMgrStartByPath(const char *path){

	int res;

	res = cmepMgrLoadByPath(path);
	if(res < 0)
		return res;

	res = cmepMgrOpen();
	if(res < 0){
		return res;
	}

	return res;
}

int _cmepMgrStop(void){

	cmepMgrClose();
	cmepMgrUnload();

	return 0;
}

int cmepMgrStart(const void *data, SceSize size){

	int res, res_mtx;

	res = ksceKernelWaitSema(global_sema, 1, NULL);
	if(res < 0)
		return res;

	res_mtx = ksceKernelLockMutex(mtx_lock, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = _cmepMgrStart(data, size);

	res_mtx = ksceKernelUnlockMutex(mtx_lock, 1);
	if(res_mtx < 0)
		res = res_mtx;

	if(res < 0)
		ksceKernelSignalSema(global_sema, 1);

	return res;
}

int cmepMgrStartByPath(const char *path){

	int res, res_mtx;

	res = ksceKernelWaitSema(global_sema, 1, NULL);
	if(res < 0)
		return res;

	res_mtx = ksceKernelLockMutex(mtx_lock, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = _cmepMgrStartByPath(path);

	res_mtx = ksceKernelUnlockMutex(mtx_lock, 1);
	if(res_mtx < 0)
		res = res_mtx;

	if(res < 0)
		ksceKernelSignalSema(global_sema, 1);

	return res;
}

int cmepMgrStop(void){

	int res, res_mtx, res_sema;

	res_mtx = ksceKernelLockMutex(mtx_lock, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = _cmepMgrStop();

	res_mtx = ksceKernelUnlockMutex(mtx_lock, 1);
	if(res_mtx < 0)
		res = res_mtx;

	res_sema = ksceKernelSignalSema(global_sema, 1);
	if(res_sema < 0)
		res = res_sema;

	return res;
}

int cmepMgrCallFunc(int cmd, void *arg, SceSize arg_len){

	int res, res_mtx;

	res_mtx = ksceKernelLockMutex(mtx_lock, 1, NULL);
	if(res_mtx < 0)
		return res_mtx;

	res = _cmepMgrCallFunc(cmd, arg, arg_len);

	res_mtx = ksceKernelUnlockMutex(mtx_lock, 1);
	if(res_mtx < 0)
		res = res_mtx;

	return res;
}

int cmepMgrInitialize(void){

	int res;
	SceKblParam *pKblParam;
	SceUInt32 version;

	pKblParam = (SceKblParam *)ksceKernelSysrootGetKblParam();
	if(pKblParam == NULL){
		return -1;
	}

	version = pKblParam->current_fw_version;
	if(version < 0x3000000 || version > 0x3740000){
		return -1;
	}

	res = ksceKernelAllocMemBlock("CmepMgrArgs", 0x10208006, CMEP_MGR_ARGS_SIZE, NULL);
	if(res < 0){
		return res;
	}

	cmep_args_uid = res;

	res = ksceKernelGetMemBlockBase(cmep_args_uid, &cmep_args_base);
	if(res < 0){
		return res;
	}

	res = ksceKernelAllocMemBlock("CmepMgrStage1Base", 0x10208006, 0x1000, NULL);
	if(res < 0){
		return res;
	}

	cmep_stage1_base_uid = res;

	res = ksceKernelGetMemBlockBase(cmep_stage1_base_uid, &cmep_stage1_base);
	if(res < 0){
		return res;
	}

	res = ksceKernelCreateMutex("CmepMgrLock", 0, 0, NULL);
	if(res < 0){
		return res;
	}

	mtx_lock = res;

	res = ksceKernelCreateSema("CmepMgrApi", 0, 1, 1, 0);
	if(res < 0){
		return res;
	}

	global_sema = res;

	cmep_stage2_base_uid = -1;

	return 0;
}
