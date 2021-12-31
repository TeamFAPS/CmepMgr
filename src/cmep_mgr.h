/*
 * CmepMgr
 * Copyright (C) 2021, Princess of Sleeping
 */

#ifndef _PSP2_CMEP_MGR_H_
#define _PSP2_CMEP_MGR_H_

int cmepMgrStart(const void *data, SceSize size);
int cmepMgrStartByPath(const char *path);
int cmepMgrStop(void);

int cmepMgrCallFunc(int cmd, void *arg, SceSize arg_len);

void cmepMgrDcacheCleanRange(const void *ptr, SceSize size);
void cmepMgrDcacheInvalidateRange(const void *ptr, SceSize size);

#endif /* _PSP2_CMEP_MGR_H_ */
