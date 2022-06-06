#pragma once
#include <ntifs.h>


NTSTATUS HideDriverByName(PWCHAR szDriverName);

NTSTATUS HideDriver(PDRIVER_OBJECT DriverObject);
