
#ifndef _PSP2_KERNEL_SBL_AUTH_INFO_H_
#define _PSP2_KERNEL_SBL_AUTH_INFO_H_

typedef struct SceSblSmCommContext130 // size is 0x130 as its name indicates
{
	uint32_t unk_0;
	uint32_t self_type;                    // kernel = 0, user = 1, sm = 2
	SceSelfAuthInfo caller_self_auth_info; // can be obtained with sceKernelGetSelfInfoForKernel
	SceSelfAuthInfo called_self_auth_info; // set by F00D in F00D SceSblSmCommContext130 response
	int path_id;                           // can be obtained with sceSblACMgrGetPathIdForKernel or sceIoGetPathIdExForDriver
	uint32_t unk_12C;
} SceSblSmCommContext130;

#endif /* _PSP2_KERNEL_SBL_AUTH_INFO_H_ */
