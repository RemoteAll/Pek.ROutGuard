/*++
Pek.ROutGuard 文件过滤驱动 —— M0 骨架（只观测，不修改任何数据）

设计原则（M0）：
  1. **绝不修改任何读写数据**：只记计数，保证零数据损坏风险；
  2. 回调里不做阻塞操作、不分配大内存、不发用户态消息；
  3. 通过 IOCTL 暴露统计，供用户态 `pek-outguard-client driver stats` 查询。

后续阶段（M1+）才会加入：规则表、密钥下发、XTS 加解密。
--*/

#include <fltKernel.h>
#include <ntstrsafe.h>

#define OUG_POOL_TAG        'GdOP'

/* 高度必须落在加密区间(400000-409999)，且避开本机已有的
   tbprotect(404001) / BzProtect(289417)，否则会因高度冲突加载失败。 */
#define OUG_ALTITUDE        L"404900"

#define OUG_DEVICE_NAME     L"\\Device\\PekOutGuardFilter"
#define OUG_SYMLINK_NAME    L"\\DosDevices\\PekOutGuardFilter"

/* 统计（原子累加，回调里零锁） */
typedef struct _OUG_STATS {
    LONGLONG Create;
    LONGLONG Read;
    LONGLONG Write;
    LONGLONG SetInfo;
    LONGLONG Cleanup;
} OUG_STATS, *POUG_STATS;

static PFLT_FILTER  g_Filter = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static OUG_STATS    g_Stats;
static volatile LONG g_Enabled = 1;

static const UNICODE_STRING g_DeviceName  = RTL_CONSTANT_STRING(OUG_DEVICE_NAME);
static const UNICODE_STRING g_SymlinkName = RTL_CONSTANT_STRING(OUG_SYMLINK_NAME);

/* ————— IOCTL 定义（与用户态保持一致）————— */

#define OUG_DEVICE_TYPE      0x8A00

#define OUG_IOCTL_GET_STATS  CTL_CODE(OUG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_SET_ENABLED CTL_CODE(OUG_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_GET_VERSION CTL_CODE(OUG_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define OUG_VERSION_MAJOR 0
#define OUG_VERSION_MINOR 1

/* ————— 回调 ————— */

FLT_PREOP_CALLBACK_STATUS
OugPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Create);
    /* M0：只计数。M1 起在这里做规则判定 + 建立每文件上下文。 */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
OugPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Read);
    /* M2 起：Post 回调里解密读取到的数据。 */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
OugPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Write);
    /* M2 起：这里加密待写入的数据。 */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
OugPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.SetInfo);
    /* M3 起：文件截断(EOF)/重命名 需要按块边界处理尾部。 */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
OugPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Cleanup);
    /* M1 起：释放每文件上下文与密钥引用。 */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* 前向声明：定义在注册结构之后 */
static NTSTATUS OugFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {    { IRP_MJ_CREATE,           0, OugPreCreate,          NULL },
    { IRP_MJ_READ,             0, OugPreRead,            NULL },
    { IRP_MJ_WRITE,            0, OugPreWrite,           NULL },
    { IRP_MJ_SET_INFORMATION,  0, OugPreSetInformation,  NULL },
    { IRP_MJ_CLEANUP,          0, OugPreCleanup,         NULL },
    /* 注意：WDK 26100 起旧名 IRP_MJ_OPERATION_END_OF_QUEUE 已被移除，
       正确的结束标记是 IRP_MJ_OPERATION_END（即 (UCHAR)0x80）。 */
    { IRP_MJ_OPERATION_END }
};

/* ————— 实例 ————— */

NTSTATUS
OugInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    /* 只挂接磁盘卷；网络/光驱/CD 等不挂，减少影响面。 */
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION g_Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                      /* Flags */
    NULL,                   /* ContextRegistration */
    g_Callbacks,            /* OperationRegistration */
    /* 字段顺序必须严格按 FLT_REGISTRATION 定义：
       卸载回调在第 6 位，实例建立回调在第 7 位。
       写反了会在卸载时以错误签名被调用 → 蓝屏。 */
    OugFilterUnload,        /* FilterUnloadCallback */
    OugInstanceSetup,       /* InstanceSetupCallback */
    NULL,                   /* InstanceQueryTeardownCallback */
    NULL,                   /* InstanceTeardownStartCallback */
    NULL,                   /* InstanceTeardownCompleteCallback */
    NULL,                   /* GenerateFileNameCallback */
    NULL,                   /* NormalizeNameComponentCallback */
    NULL,                   /* NormalizeNameComponentExCallback */
    NULL, NULL, NULL        /* SectionNotification / NormalizeNameComponent2 / GenerateFileName2 */
};

/* ————— IOCTL 控制通道 ————— */

static NTSTATUS
OugCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
OugDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG outLen = 0;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case OUG_IOCTL_GET_STATS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(OUG_STATS)) {
            /* 直接读快照：16 字节对齐的 64 位原子读，无需加锁。 */
            *(POUG_STATS)buffer = g_Stats;
            outLen = sizeof(OUG_STATS);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case OUG_IOCTL_SET_ENABLED:
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(LONG)) {
            LONG value = *(PLONG)buffer;
            InterlockedExchange(&g_Enabled, value ? 1 : 0);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case OUG_IOCTL_GET_VERSION:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG)) {
            *(PULONG)buffer = ((ULONG)OUG_VERSION_MAJOR << 16) | OUG_VERSION_MINOR;
            outLen = sizeof(ULONG);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
OugCreateControlDevice(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        (PUNICODE_STRING)&g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink((PUNICODE_STRING)&g_SymlinkName,
                                  (PUNICODE_STRING)&g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = OugCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = OugCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OugDeviceControl;
    return STATUS_SUCCESS;
}

static VOID
OugDeleteControlDevice(VOID)
{
    if (g_DeviceObject != NULL) {
        IoDeleteSymbolicLink((PUNICODE_STRING)&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

/* ————— 卸载 ————— */

/* 签名必须与 PFLT_FILTER_UNLOAD_CALLBACK 一致：NTSTATUS(FLT_FILTER_UNLOAD_FLAGS) */
static NTSTATUS
OugFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_Filter != NULL) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }
    OugDeleteControlDevice();
    DbgPrint("[PekOutGuard] driver unloaded\n");
    return STATUS_SUCCESS;
}

/* ————— 入口 ————— */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DbgPrint("[PekOutGuard] DriverEntry begin\n");

    /* minifilter 的卸载走 FilterUnloadCallback，不需要 DriverObject->DriverUnload。 */
    status = OugCreateControlDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PekOutGuard] IoCreateDevice failed 0x%08X\n", status);
        return status;
    }

    status = FltRegisterFilter(DriverObject, &g_Registration, &g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PekOutGuard] FltRegisterFilter failed 0x%08X\n", status);
        OugDeleteControlDevice();
        return status;
    }

    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PekOutGuard] FltStartFiltering failed 0x%08X\n", status);
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
        OugDeleteControlDevice();
        return status;
    }

    DbgPrint("[PekOutGuard] loaded OK (M0: observe-only)\n");
    return STATUS_SUCCESS;
}
