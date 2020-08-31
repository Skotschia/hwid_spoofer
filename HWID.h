#pragma once

#include "NT.h"
namespace HWID {
	NTSTATUS ClearPropertyDriveSerials();
	NTSTATUS ClearSMBIOS();
	NTSTATUS ClearSmartDriveSerials();

	struct CompletionRoutineInfo {
		PIO_COMPLETION_ROUTINE oldRoutine;
		PVOID oldContext;
	};
}