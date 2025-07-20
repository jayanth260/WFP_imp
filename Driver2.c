//#include <ws2tcpip.h>
#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblapi.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>

#include <wdf.h>
#include <ip2string.h>



//#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Fwpkclnt.lib")

#define INITGUID
#include <guiddef.h>

DEFINE_GUID(
    REDIRECT_CALLOUT_GUID,
    0xaabbccdb, 0xeeff, 0x1122,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
);

DEFINE_GUID(
    REDIRECT_CALLOUT2_GUID,
    0xaabbccdb, 0xeeff, 0x1122,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x01
);

DEFINE_GUID(
    FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
    0xc6e63c8c,
    0xb784,
    0x4562,
    0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3
);

DEFINE_GUID(
    FWPM_LAYER_ALE_BIND_REDIRECT_V4,
    0x66978cad,
    0xc704,
    0x42ac,
    0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53
);

DEFINE_GUID(
    FWPM_CONDITION_IP_LOCAL_ADDRESS,
    0xd9ee00de,
    0xc1ef,
    0x4617,
    0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57
);

DEFINE_GUID(
    FWPM_CONDITION_IP_REMOTE_ADDRESS,
    0xb235ae9a,
    0x1d64,
    0x49b8,
    0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45
);


DEFINE_GUID(
    REDIRECT_SUBLAYER_GUID,
    0xaabbccdd, 0xeeff, 0x2233,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
);

DEFINE_GUID(
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38d57d1,
    0x05a7,
    0x4c33,
    0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

DEFINE_GUID(
    FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
    0xaf80470a,
    0x5596,
    0x4c13,
    0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67
);




// Global variables

UINT32 gCalloutId = 0;
UINT32 gFilterId = 0;
UINT32 gCalloutId2 = 0;
UINT32 gFilterId2 = 0;
HANDLE g_RedirectHandle = NULL;
const char* serverIp = "40.192.39.82";

const UINT32 gTargetInterfaceIndex = 11;

// Forward declarations
void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI NotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER0* filter
);

void NTAPI FlowDeleteFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext);

VOID Unload(_In_ PDRIVER_OBJECT DriverObject);


#pragma alloc_text(PAGE, Unload)

VOID SetSocketIPv4Addr(SOCKADDR_INET* addrAndPort, IN_ADDR newAddr) {
    if (addrAndPort == NULL) {
        KdPrint(("SetSocketIPv4Addr: NULL address parameter\n"));
        return;
    }

    if (addrAndPort->si_family == AF_INET) {
        addrAndPort->Ipv4.sin_addr = newAddr;
    }
    else {
        KdPrint(("SetSocketIPv4Addr: Unsupported address family: %d\n", addrAndPort->si_family));
    }
}

void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
) {
    UNREFERENCED_PARAMETER(inMetaValues);
    
    UNREFERENCED_PARAMETER(flowContext);
    KdPrint(("entered classify\n"));

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;

   
    if (layerData == NULL) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    if (inFixedValues == NULL)
    {
        return;
    }
    if (classifyContext == NULL)
    {
        KdPrint(("Classify context is NULL\n"));
     
        classifyOut->actionType = FWP_ACTION_CONTINUE;

        return;
	}

    if (inFixedValues->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4)
    {
        return;
    }
	KdPrint(("Layer ID: %u\n", inFixedValues->layerId));

    /*UINT8 protocol = inFixedValues->incomingValue[FWPM_LAYER_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    if (protocol != IPPROTO_UDP) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }*/
    // // Avoid reinjection loop
    // if (FwpsQueryPacketInjectionState(gInjectionHandle, layerData, NULL) != FWPS_PACKET_INJECTION_STATE_NOT_INJECTED)
    //     return;
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST* connectReq = NULL;


    
    auto status = FwpsAcquireClassifyHandle(classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
        {
		KdPrint(("Failed to acquire classify handle: 0x%X\n", status));
            return;
        }
	KdPrint(("Classify handle acquired\n"));

    status = FwpsAcquireWritableLayerDataPointer(classifyHandle,
            filter->filterId, 0, &connectReq, classifyOut);
    if (!NT_SUCCESS(status))
        {
            return;
        }
	KdPrint(("Writable layer data pointer acquired\n"));

    IN_ADDR TargetAddr;
    PCSTR endptr;
    NTSTATUS convStatus = RtlIpv4StringToAddressA("10.1.129.197", TRUE, &endptr, &TargetAddr);

    SetSocketIPv4Addr(&connectReq->localAddressAndPort, TargetAddr);
	KdPrint(("Set local address\n"));

    if (connectReq != NULL)
        {
            FwpsApplyModifiedLayerData(classifyHandle, connectReq, 0);
        }

    if (classifyHandle != 0)
        {
            FwpsReleaseClassifyHandle(classifyHandle);
        }

	KdPrint(("Classify function completed\n"));
	  


}


void NTAPI ClassifyFn2(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
) {
    UNREFERENCED_PARAMETER(inMetaValues);

    UNREFERENCED_PARAMETER(flowContext);
    KdPrint(("entered classify CONNECT\n"));

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return;

    // Defensive: if no data, continue
    if (layerData == NULL) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    if (inFixedValues == NULL)
    {
        return;
    }

    if (inFixedValues->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
    {
        return;
    }

    if( classifyContext == NULL)
    {
        KdPrint(("Classify context is NULL\n"));
        
	}
    
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST* connectReq = NULL;


    auto status = FwpsAcquireClassifyHandle(classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    KdPrint(("Classify handle acquired\n"));

    status = FwpsAcquireWritableLayerDataPointer(classifyHandle,
        filter->filterId, 0, &connectReq, classifyOut);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    KdPrint(("Writable layer data pointer acquired\n"));

    IN_ADDR TargetAddr;
    PCSTR endptr;
    NTSTATUS convStatus = RtlIpv4StringToAddressA("192.168.128.183", TRUE, &endptr, &TargetAddr);
    
    SetSocketIPv4Addr(&connectReq->localAddressAndPort, TargetAddr);
    KdPrint(("Set local address\n"));

    if (connectReq != NULL)
    {
        FwpsApplyModifiedLayerData(classifyHandle, connectReq, 0);
    }

    if (classifyHandle != 0)
    {
        FwpsReleaseClassifyHandle(classifyHandle);
    }

    KdPrint(("Classify function completed\n"));



}

void NTAPI ClassifyFn_inject(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER3* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
)
{
    
}

NTSTATUS NTAPI NotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER0* filter
) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI FlowDeleteFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

NTSTATUS RegisterCallout(PDEVICE_OBJECT deviceObject) {

    

    NTSTATUS status;

    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = REDIRECT_CALLOUT_GUID;
    callout.classifyFn = ClassifyFn_inject;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;
    callout.flags = 0x00000001;

    KdPrint(("Registering callout...\n"));
    status = FwpsCalloutRegister(deviceObject, &callout, &gCalloutId);
    if (!NT_SUCCESS(status))
        return status;
    KdPrint(("Callout1 registered\n"));


	/*FWPS_CALLOUT callout2 = { 0 };
	callout2.calloutKey = REDIRECT_CALLOUT2_GUID;
	callout2.classifyFn = ClassifyFn2;
	callout2.notifyFn = NotifyFn;
	callout2.flowDeleteFn = FlowDeleteFn;

	KdPrint(("Registering callout2...\n"));
	status = FwpsCalloutRegister(deviceObject, &callout2, &gCalloutId2);
    if (!NT_SUCCESS(status))
		return status;
	KdPrint(("Callout2 registered\n"));*/
    // Add callout to WFP engine
    FWPM_CALLOUT mCallout = { 0 };
    mCallout.calloutKey = REDIRECT_CALLOUT_GUID;
    mCallout.displayData.name = L"Redirect Callout";
    mCallout.displayData.description = L"Redirect TCP packets to specific interface";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    KdPrint(("mCallout created\n"));


    
	// Add second callout to WFP engine
	/*FWPM_CALLOUT mCallout2 = { 0 };
	mCallout2.calloutKey = REDIRECT_CALLOUT2_GUID;
	mCallout2.displayData.name = L"Redirect Callout2";
	mCallout2.displayData.description = L"Redirect TCP packets to specific interface2";
	mCallout2.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

	KdPrint(("mCallout2 created\n"));*/

    HANDLE engineHandle = NULL;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status))
        return status;

    status = FwpmCalloutAdd(engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }

    KdPrint(("Callout added\n"));


	/*status = FwpmCalloutAdd(engineHandle, &mCallout2, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
	}
	KdPrint(("Callout2 added\n"));*/

    FWPM_SUBLAYER subLayer = { 0 };
    subLayer.subLayerKey = REDIRECT_SUBLAYER_GUID;
    subLayer.displayData.name = L"Redirect Sublayer";
    subLayer.displayData.description = L"Custom sublayer for redirect callout";
    subLayer.flags = 0;
    subLayer.weight = 0x100;

    status = FwpmSubLayerAdd(engineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }

	KdPrint(("Sublayer added\n"));

    FWP_V4_ADDR_AND_MASK addrMask = { 0 };
    IN_ADDR addr;
    PCSTR endptr;
    NTSTATUS convStatus = RtlIpv4StringToAddressA("40.192.39.82", TRUE, &endptr, &addr);
    if (NT_SUCCESS(convStatus)) {
        // Print the converted IP address
        KdPrint(("Converted IP: %u.%u.%u.%u (0x%08X)\n",
            (addr.S_un.S_addr >> 0) & 0xFF,
            (addr.S_un.S_addr >> 8) & 0xFF,
            (addr.S_un.S_addr >> 16) & 0xFF,
            (addr.S_un.S_addr >> 24) & 0xFF,
            addr.S_un.S_addr));

        addrMask.addr = addr.S_un.S_addr;  // Don't forget this line!
        addrMask.mask = 0xFFFFFFFF;
    }
    else {
        KdPrint(("Failed to convert IP address, status: 0x%08X\n", convStatus));
    }
    //addrMask.mask = 0xFFFFFFFF; // Exact match

    FWPM_FILTER_CONDITION conditions[1] = { 0 };

    conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_V4_ADDR_MASK;
    conditions[0].conditionValue.v4AddrMask = &addrMask;

    FWPM_FILTER_CONDITION conditions1[1] = { 0 };

    // Add filter to attach callout
    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"Redirect all outbound UDP to interface";
    filter.displayData.description = L"Redirect all outbound UDP packets to specific interface";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = REDIRECT_CALLOUT_GUID;
    filter.filterCondition = conditions;
    filter.numFilterConditions = 1;
    filter.subLayerKey = REDIRECT_SUBLAYER_GUID; // Use universal sublayer
    filter.weight.type = FWP_EMPTY; // auto-weight

    status = FwpmFilterAdd(engineHandle, &filter, NULL, &gFilterId);
    KdPrint(("Filter1 added\n"));

 //   FWPM_FILTER filter2 = { 0 };
	//filter2.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
	//filter2.displayData.name = L"Redirect all outbound TCP to interface";
	//filter2.displayData.description = L"Redirect all outbound TCP packets to specific interface";
	//filter2.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	//filter2.action.calloutKey = REDIRECT_CALLOUT2_GUID;
	//filter2.filterCondition = conditions;
	//filter2.numFilterConditions = 1;
	//filter2.subLayerKey = REDIRECT_SUBLAYER_GUID; // Use universal sublayer
	//filter2.weight.type = FWP_EMPTY; // auto-weight

 //   status = FwpmFilterAdd(engineHandle, &filter2, NULL, &gFilterId2);
 //   KdPrint(("Filter2 added\n"));


    
	

    FwpmEngineClose(engineHandle);

    return status;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("Driver Unloading...\n"));

    if (gCalloutId != 0) {
		KdPrint(("Unregistering callout...\n"));
		KdPrint(("gCalloutId: %u\n", gCalloutId));
        FwpsCalloutUnregisterById(gCalloutId);
        gCalloutId = 0;
    }
	if (gCalloutId2 != 0) {
		KdPrint(("Unregistering callout2...\n"));
		KdPrint(("gCalloutId2: %u\n", gCalloutId2));
        FwpsCalloutUnregisterById(gCalloutId2);
        gCalloutId2 = 0;
	}

    if (gFilterId != 0) {
        HANDLE engineHandle = NULL;
        if (NT_SUCCESS(FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle))) {
            FwpmFilterDeleteById(engineHandle, gFilterId);
            FwpmEngineClose(engineHandle);
        }
        gFilterId = 0;
    }
    if (gFilterId2 != 0) {
        HANDLE engineHandle = NULL;
        if (NT_SUCCESS(FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle))) {
            FwpmFilterDeleteById(engineHandle, gFilterId2);
            FwpmEngineClose(engineHandle);
        }
        gFilterId2 = 0;
	}

}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DriverObject->DeviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create the filter device object (0x%X).\n", status));
        return status;
    }

    DriverObject->DriverUnload = Unload;

    KdPrint(("Driver Loaded\n"));

    return RegisterCallout(DriverObject->DeviceObject);
}