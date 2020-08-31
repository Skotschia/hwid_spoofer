#include "HWID.h"
#include "util.h"
#include <ntdddisk.h>

NTSTATUS ( *originalDeviceControl )( PDEVICE_OBJECT , PIRP ) {};

NTSTATUS smartRcvDriveDataCompletion ( PDEVICE_OBJECT deviceObject , PIRP irp , HWID::CompletionRoutineInfo* context ) {
	const auto ioStack = IoGetCurrentIrpStackLocation ( irp );

	if ( ioStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof ( SENDCMDOUTPARAMS ) ) {
		const auto serial = reinterpret_cast< PIDINFO >( reinterpret_cast< PSENDCMDOUTPARAMS >(
			irp->AssociatedIrp.SystemBuffer )->bBuffer )->sSerialNumber;

		memset ( serial , 0 , sizeof ( CHAR ) );
	}

	if ( context->oldRoutine && irp->StackCount > 1 ) {
		const auto oldRoutine = context->oldRoutine;
		const auto oldContext = context->oldContext;
		return oldRoutine ( deviceObject , irp , oldContext );
	}

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHook ( const PDEVICE_OBJECT deviceObject , const PIRP irp ) {
	const auto stackLocation = IoGetCurrentIrpStackLocation ( irp );
	switch ( stackLocation->Parameters.DeviceIoControl.IoControlCode ) {
	case SMART_RCV_DRIVE_DATA: {
		const auto context = reinterpret_cast< HWID::CompletionRoutineInfo* >( ExAllocatePool ( NonPagedPool ,
			sizeof ( HWID::CompletionRoutineInfo ) ) );
		context->oldRoutine = stackLocation->CompletionRoutine;
		context->oldContext = stackLocation->Context;
		stackLocation->CompletionRoutine = reinterpret_cast< PIO_COMPLETION_ROUTINE >( smartRcvDriveDataCompletion );
		stackLocation->Context = context;
		break;
	}
	}

	return originalDeviceControl ( deviceObject , irp );
}

NTSTATUS HWID::ClearPropertyDriveSerials ( ) {
	// dont null the serials but randomise instead
	// returns STATUS_SUCCESS if the nulling off the property drive serials  was successful. 
	//  nulls it by using memset

	//Improve:
	//-Dont NULL the serials, but randomise.

	std::uint8_t serialNumberOffset {};
	{ // Find the serial number offset
		std::uintptr_t storportBase {};
		std::size_t storportSize {};
		Nt::findKernelModuleByName ( "storport.sys" , &storportBase , &storportSize );  // grabs the storport.sys base 

		if ( !storportBase ) { return STATUS_INVALID_ADDRESS; }


		// The code we're looking for is in the page section
		std::uintptr_t storportPage {};
		std::size_t storportPageSize {};
		Nt::findModuleSection ( storportBase , "PAGE" , &storportPage , &storportPageSize );

		if ( !storportPage ) { return STATUS_INVALID_ADDRESS; }


		const auto serialNumberFunc = SigScan::scanPattern ( reinterpret_cast< std::uint8_t* >( storportPage ) , storportPageSize ,
			"\x66\x41\x3B\xF8\x72\xFF\x48\x8B\x53" , "xxxxx?xxx" );  // scans for the function which contains the serialnumbers

		if ( !serialNumberFunc ) { return STATUS_INVALID_ADDRESS; }


		serialNumberOffset = *reinterpret_cast< std::uint8_t* >( serialNumberFunc + 0x9 );
		if ( !serialNumberOffset ) { return STATUS_INVALID_ADDRESS; }

	}

	const auto diskDriver = Nt::findDriverObjectByName ( L"\\Driver\\Disk" );

	if ( !diskDriver ) { return STATUS_NOT_FOUND; }


	auto currentDevice = diskDriver->DeviceObject;
	while ( currentDevice ) {
		auto physicalDriveObject = *reinterpret_cast< PDEVICE_OBJECT* >( reinterpret_cast< std::uintptr_t >( currentDevice->DeviceExtension ) + 0x200 );

		if ( !physicalDriveObject ) {
			physicalDriveObject = *reinterpret_cast< PDEVICE_OBJECT* >( reinterpret_cast< std::uintptr_t >( currentDevice->DeviceExtension ) + 0x10 );

		}

		const auto serialNumber = *reinterpret_cast< char** >( reinterpret_cast< std::uintptr_t >( physicalDriveObject->DeviceExtension ) + serialNumberOffset );
		if ( !MmIsAddressValid ( serialNumber ) ) {
			currentDevice = currentDevice->NextDevice;
			continue;
		}

		auto Test = currentDevice->Size;
		memset ( serialNumber , 0 , sizeof ( char** ) );

		currentDevice = currentDevice->NextDevice;
	}

	return STATUS_SUCCESS;
}

NTSTATUS HWID::ClearSmartDriveSerials ( ) {

	// find alternative for irp hook or use a stealthy irp hook
	// dont null the serials but randomise instead
	// returns STATUS_SUCCESS if the nulling off the smart drive serials  was successful. 
	//  nulls it by using memset


	//Improve:
	//-Dont NULL the serials, but randomise.

	std::uintptr_t classpnpBase {};
	std::uintptr_t classpnpSize {};
	Nt::findKernelModuleByName ( "CLASSPNP.SYS" , &classpnpBase , &classpnpSize ); // grabs the classpnp.sys base 

	if ( !classpnpBase ) { return STATUS_NOT_FOUND; }


	const auto diskDriver = Nt::findDriverObjectByName ( L"\\Driver\\Disk" );

	if ( !diskDriver ) { return STATUS_NOT_FOUND; }


	const auto majorFunctionTableFunc = SigScan::scanPattern ( reinterpret_cast< std::uint8_t* >( diskDriver->MajorFunction [ IRP_MJ_DEVICE_CONTROL ] ) , // find alternative for irp hook
		0x100 , "\x49\x8B\x81\xFF\xFF\xFF\xFF\x4A\x8B\x04\xC0\xFF\x15" , "xxx????xxxxxx" );

	if ( !majorFunctionTableFunc ) { return STATUS_NOT_FOUND; }


	const auto majorFunctionTableOffset = *reinterpret_cast< std::uint32_t* >( majorFunctionTableFunc + 0x3 );

	if ( !majorFunctionTableOffset ) { return STATUS_NOT_FOUND; }


	auto currentDevice = diskDriver->DeviceObject;
	std::size_t i {};

	const auto majorFunctionTable = *reinterpret_cast< std::uintptr_t** >( reinterpret_cast< std::uintptr_t >( currentDevice->DeviceExtension ) + majorFunctionTableOffset );
	originalDeviceControl = reinterpret_cast< decltype( originalDeviceControl ) >( majorFunctionTable [ IRP_MJ_DEVICE_CONTROL ] );
	while ( currentDevice ) {
		const auto majorFunctionTable = *reinterpret_cast< std::uintptr_t** >( reinterpret_cast< std::uintptr_t >( currentDevice->DeviceExtension ) + majorFunctionTableOffset );
		majorFunctionTable [ IRP_MJ_DEVICE_CONTROL ] = reinterpret_cast< std::uintptr_t >( &DeviceControlHook );

		currentDevice = currentDevice->NextDevice; ++i;
	}

	return STATUS_SUCCESS;
}


NTSTATUS HWID::ClearSMBIOS ( )
{

	/// Gets base of ntoskrnl.sys 
	/// scans for the physical memory address signature 
	/// gets the physical address and size
	///  nulls it by using memset
	/// returns STATUS_SUCCESS if the nulling off the smbios was successful. 

	//Improve:
	//-Dont NULL the serials, but randomise.

	std::size_t size {};
	std::uintptr_t ntoskrnlBase {};
	if ( !NT_SUCCESS ( Nt::findKernelModuleByName ( "ntoskrnl.exe" , &ntoskrnlBase , &size ) ) )
		return false;

	PPHYSICAL_ADDRESS SMBIOSTableSignature = reinterpret_cast< PPHYSICAL_ADDRESS >( SigScan::scanPattern ( reinterpret_cast< std::uint8_t* >( ntoskrnlBase ) , size , "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15" , "xxx????xxxx?xx" ) );
	// located  at  WmipSMBiosTablePhysicalAddres
	if ( !SMBIOSTableSignature ) { return STATUS_NOT_FOUND; }


	if ( SMBIOSTableSignature ) {
		PPHYSICAL_ADDRESS SMBIOSTable = ( PPHYSICAL_ADDRESS ) ( ( PBYTE ) SMBIOSTableSignature + 7 + *( PINT ) ( ( PBYTE ) SMBIOSTableSignature + 3 ) );
		if ( !SMBIOSTable ) { return STATUS_NOT_FOUND; }

		memset ( SMBIOSTable , 0 , sizeof ( PHYSICAL_ADDRESS ) );
	}

	return STATUS_SUCCESS;
}