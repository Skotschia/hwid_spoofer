
#include "HWID.h"

NTSTATUS DriverEntry ( const PDRIVER_OBJECT driverObject , const PUNICODE_STRING registryPath )
{

	// instead of nulling the serials - randomise. 
	// Change the hook, or use a stealthy irp hook. 
	// remove the vulnerable driver you mapped with from piddcache and mmunloaded. // if your manual mapping.
	HWID::ClearPropertyDriveSerials ( );
	HWID::ClearSmartDriveSerials ( );
	HWID::ClearSMBIOS ( );


	return STATUS_SUCCESS;
}