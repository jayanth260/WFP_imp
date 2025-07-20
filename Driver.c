#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblapi.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#include <ip2string.h>

#pragma comment(lib, "Fwpkclnt.lib")

#define INITGUID
#include <guiddef.h>


DEFINE_GUID(
    REDIRECT_CALLOUT_GUID,
    0xaabbccdd, 0xeeff, 0x1122,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
);

DEFINE_GUID(
    FWPM_LAYER_STREAM_V4,
    0x3b89653c,
    0xc170,
    0x49e4,
    0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e
);

DEFINE_GUID(
    REDIRECT_TCP_CALLOUT_GUID,
    0xaabbccdd, 0xeeff, 0x1122,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x10
);

DEFINE_GUID(
    FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
    0xc6e63c8c,
    0xb784,
    0x4562,
    0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3
);

DEFINE_GUID(
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
    0x09e61aea,
    0xd214,
    0x46e2,
    0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8
);

DEFINE_GUID(
    REDIRECT_SUBLAYER_GUID,
    0xaabbccdd, 0xeeff, 0x2233,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
);

DEFINE_GUID(
    FWPM_CONDITION_IP_REMOTE_ADDRESS,
    0xb235ae9a,
    0x1d64,
    0x49b8,
    0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45
);
// Global variables
HANDLE gInjectionHandle = NULL;
UINT32 gCalloutId = 0;
UINT32 gFilterId = 0;
UINT32 gCallout2Id = 0;
UINT32 gFilter2Id = 0;
NDIS_HANDLE gNblPoolHandle = NULL;
const UINT32 gTargetInterfaceIndex = 12;
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

VOID NTAPI
InjectCompleteCallback(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
) {
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(dispatchLevel);

    // Free the cloned NBL that we injected
    FwpsFreeCloneNetBufferList0(netBufferList, 0);

    KdPrint(("Injection completed\n"));
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
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    KdPrint(("entered classify UDP\n"));

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {   
        KdPrint(("no rights\n"));
        return;
    }
    if (layerData == NULL) {
        KdPrint(("no data\n"));
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    if (FwpsQueryPacketInjectionState(gInjectionHandle, layerData, NULL) == FWPS_PACKET_INJECTED_BY_SELF)
    {
        KdPrint(("Avoiding reinjection loop\n"));
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
    KdPrint(("Protocol: %d\n", protocol));

    //return;

    /*if (protocol != IPPROTO_UDP) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }*/

    KdPrint(("Processing All Packets\n"));

    if (gNblPoolHandle == NULL) {
        KdPrint(("NBL pool handle is NULL\n"));
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    __try {
        if (!layerData || !gNblPoolHandle) {
            classifyOut->actionType = FWP_ACTION_CONTINUE;
            return;
        }

        NET_BUFFER_LIST* originalNbl = (NET_BUFFER_LIST*)layerData;
        NET_BUFFER_LIST* clonedNbl = NULL;

        KdPrint(("Attempting to clone NBL %p\n", originalNbl));
        NTSTATUS status = FwpsAllocateCloneNetBufferList0(
            originalNbl,
            gNblPoolHandle,
            NULL,
            0,
            &clonedNbl
        );

        if (!NT_SUCCESS(status) || clonedNbl == NULL) {
            KdPrint(("Clone failed with status: 0x%X\n", status));
            classifyOut->actionType = FWP_ACTION_CONTINUE;
            return;
        }

        KdPrint(("Cloned Successfully\n"));
        KdPrint(("%d\n", clonedNbl->FirstNetBuffer->DataLength));
        if(clonedNbl->Next != NULL && clonedNbl->Next->FirstNetBuffer!=NULL)
		KdPrint(("---%d\n", clonedNbl->Next->FirstNetBuffer->DataLength));
        //status = FwpsInjectTransportSendAsync0(
        //    gInjectionHandle,
        //    NULL,                          // Injection context
        //    0,                             // Endpoint handle (0 for transport)
        //    0,                             // Flags
        //    NULL,
        //    AF_INET,                       // Address family
        //    inMetaValues->compartmentId,   // 
        //    clonedNbl,
        //    NULL,                          // Completion function
        //    NULL                           // Completion context
        //);

        status = FwpsInjectForwardAsync0(
            gInjectionHandle,
            NULL,
            0,
            AF_INET,
            inMetaValues->compartmentId, // Compartment ID
            gTargetInterfaceIndex,       // Redirect interface index
            clonedNbl,
            InjectCompleteCallback,                        // Completion function
            NULL                         // Completion context  
        );

        if (NT_SUCCESS(status)) {
            KdPrint(("Injection successful\n"));
            classifyOut->actionType = FWP_ACTION_BLOCK; // Block original packet
        }
        else {
            KdPrint(("Injection failed with status: 0x%X\n", status));
            FwpsFreeCloneNetBufferList0(clonedNbl, 0);
            classifyOut->actionType = FWP_ACTION_CONTINUE;
        }
      return;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("EXCEPTION during NBL clone operation: 0x%X\n", GetExceptionCode()));
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    //  KdPrint(("Cloned Successfully\n"));

    //  FwpsFreeCloneNetBufferList0(clonedNbl, 0);

    //  classifyOut->actionType = FWP_ACTION_CONTINUE;

    //  return;



    //  // Inject cloned packet redirecting to target interface

    //  status = FwpsInjectForwardAsync0(
    //      gInjectionHandle,
    //      NULL,                          // Injection context
    //      0,                             // Flags

    //      AF_INET,

    //      inMetaValues->compartmentId,   // Compartment ID

    //      gTargetInterfaceIndex,         // Redirect interface index

    //      clonedNbl,

    //      NULL,                          // Completion Fn

    //      NULL                           // Completion context

    //  );





    //  if (NT_SUCCESS(status)) {

          //KdPrint(("Injection successful\n"));

    //      classifyOut->actionType = FWP_ACTION_BLOCK; // Block original, we reinject clone

    //  }

    //  else {

          //KdPrint(("Injection failed with status: 0x%X\n", status));

    //      classifyOut->actionType = FWP_ACTION_CONTINUE;

    //      FwpsFreeCloneNetBufferList0(clonedNbl, 0);

    //  }



      //KdPrint(("redirecting through interface: %d\n", gTargetInterfaceIndex));


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



    if (classifyContext == NULL)

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

    NTSTATUS convStatus = RtlIpv4StringToAddressA("192.168.212.183", TRUE, &endptr, &TargetAddr);



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
    HANDLE engineHandle = NULL;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (!NT_SUCCESS(status))
        return status;
    FWPS_CALLOUT callout = { 0 };
    callout.calloutKey = REDIRECT_CALLOUT_GUID;
    callout.classifyFn = ClassifyFn;
    callout.notifyFn = NotifyFn;
    callout.flowDeleteFn = FlowDeleteFn;

    KdPrint(("Registering callout...\n"));
    status = FwpsCalloutRegister(deviceObject, &callout, &gCalloutId);
    if (!NT_SUCCESS(status))
        return status;

    KdPrint(("Callout registered\n"));


    //return status;

    // Add callout to WFP engine

    FWPM_CALLOUT mCallout = { 0 };
    mCallout.calloutKey = REDIRECT_CALLOUT_GUID;
    mCallout.displayData.name = L"Modify UDP Callout";
    mCallout.displayData.description = L"Redirect UDP packets to specific interface";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd(engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }

    KdPrint(("mCallout Added\n"));

    FWPS_CALLOUT callout2 = { 0 };
    callout2.calloutKey = REDIRECT_TCP_CALLOUT_GUID;
    callout2.classifyFn = ClassifyFn2;
    callout2.notifyFn = NotifyFn;
    callout2.flowDeleteFn = FlowDeleteFn;

    KdPrint(("Registering callout2...\n"));
    status = FwpsCalloutRegister(deviceObject, &callout2, &gCallout2Id);
    if (!NT_SUCCESS(status))
        return status;

    KdPrint(("Callout2 registered\n"));

    //return status;

    // Add callout to WFP engine

    FWPM_CALLOUT mCallout2 = { 0 };
    mCallout2.calloutKey = REDIRECT_TCP_CALLOUT_GUID;
    mCallout2.displayData.name = L"Redirect Callout";
    mCallout2.displayData.description = L"Redirect TCP packets to specific interface";
    mCallout2.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

    status = FwpmCalloutAdd(engineHandle, &mCallout2, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }
    KdPrint(("mCallout2 Added\n"));

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

    KdPrint(("Sublayer Added\n"));

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

    /*conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_V4_ADDR_MASK;
    conditions[0].conditionValue.v4AddrMask = &addrMask;*/

    // Add filter to attach callout
    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.displayData.name = L"Redirect all outbound UDP to interface";
    filter.displayData.description = L"Redirect all outbound UDP packets to specific interface";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = REDIRECT_CALLOUT_GUID;
    filter.filterCondition = conditions;
    filter.numFilterConditions = 0;
    filter.subLayerKey = REDIRECT_SUBLAYER_GUID; // Use universal sublayer
    filter.weight.type = FWP_EMPTY; // auto-weight

    status = FwpmFilterAdd(engineHandle, &filter, NULL, &gFilterId);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }

    KdPrint(("Filter added\n"));

    FWPM_FILTER filter2 = { 0 };
    filter2.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter2.displayData.name = L"Redirect all outbound TCP to interface";
    filter2.displayData.description = L"Redirect all outbound TCP packets to specific interface";
    filter2.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter2.action.calloutKey = REDIRECT_TCP_CALLOUT_GUID;
    filter2.filterCondition = conditions;
    filter2.numFilterConditions = 0;
    filter2.subLayerKey = REDIRECT_SUBLAYER_GUID; // Use universal sublayer
    filter2.weight.type = FWP_EMPTY; // auto-weight

    /*status = FwpmFilterAdd(engineHandle, &filter2, NULL, &gFilter2Id);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose(engineHandle);
        return status;
    }
    KdPrint(("Filte2r added\n"));*/
    /*return status;*/

    FwpmEngineClose(engineHandle);
    return status;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    if (gInjectionHandle) {
        FwpsInjectionHandleDestroy(gInjectionHandle);
        gInjectionHandle = NULL;
    }
    if (gCalloutId != 0) {
        FwpsCalloutUnregisterById(gCalloutId);
        gCalloutId = 0;
    }

    if (gFilterId != 0) {
        HANDLE engineHandle = NULL;
        if (NT_SUCCESS(FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle))) {
            FwpmFilterDeleteById(engineHandle, gFilterId);
            FwpmEngineClose(engineHandle);
        }
        gFilterId = 0;
    }

    if (gCallout2Id != 0) {
        FwpsCalloutUnregisterById(gCallout2Id);
        gCalloutId = 0;
    }
    if (gFilter2Id != 0) {
        HANDLE engineHandle = NULL;
        if (NT_SUCCESS(FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle))) {
            FwpmFilterDeleteById(engineHandle, gFilter2Id);
            FwpmEngineClose(engineHandle);
        }
        gFilterId = 0;
    }

    if (gNblPoolHandle) {
        NdisFreeNetBufferListPool(gNblPoolHandle);
        gNblPoolHandle = NULL;
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

    // Create Injection Handle
    status = FwpsInjectionHandleCreate(
        AF_INET,
        FWPS_INJECTION_TYPE_FORWARD,
        &gInjectionHandle
    );

    if (!NT_SUCCESS(status))
        return status;

    // Create NetBufferList Pool for cloning NBLs
    {
        NET_BUFFER_LIST_POOL_PARAMETERS poolParams = { 0 };
        poolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        poolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        poolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        poolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
        poolParams.fAllocateNetBuffer = TRUE;
        poolParams.ContextSize = 0;
        poolParams.PoolTag = 'FWPN';
        poolParams.DataSize = 0;

        gNblPoolHandle = NdisAllocateNetBufferListPool(NULL, &poolParams);

        if (gNblPoolHandle == NULL) {
            KdPrint(("Failed to allocate NetBufferList pool\n"));
            FwpsInjectionHandleDestroy(gInjectionHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    KdPrint(("Injection Handle Created\n"));
    return RegisterCallout(DriverObject->DeviceObject);
}