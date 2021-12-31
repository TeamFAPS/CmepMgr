/*
 * CmepMgr
 * Copyright (C) 2021, Princess of Sleeping
 */

#include <psp2kern/kernel/modulemgr.h>
#include "cmep_mgr.h"
#include "cmep_mgr_internal.h"

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	int res;

	res = cmepMgrInitialize();
	if(res < 0)
		return SCE_KERNEL_START_FAILED;

	return SCE_KERNEL_START_SUCCESS;
}
