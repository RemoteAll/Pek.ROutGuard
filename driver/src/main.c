/*++
Pek.ROutGuard 文件过滤驱动 —— M1（规则判定 + 控制通道，**仍不修改任何数据**）

设计原则：
  1. **绝不修改任何读写数据**：M1 只“判定是否命中受控规则”并计数，零数据损坏风险；
  2. 回调里不做阻塞操作、不发用户态消息、不等待；
  3. 规则由用户态服务通过 IOCTL 下发；驱动内只做前缀/扩展名匹配。

路径口径：内核拿到的是 NT 路径（\Device\HarddiskVolume3\...），
用户态下发规则前需先用 QueryDosDevice 把 D: 换算成 \Device\HarddiskVolumeN。

后续阶段（M2+）才会加入：密钥下发、XTS 加解密。
--*/

#include <fltKernel.h>
#include <ntstrsafe.h>

#define OUG_POOL_TAG        'GdOP'

/* 高度必须落在加密区间(400000-409999)，且避开本机已有的
   tbprotect(404001) / BzProtect(289417)，否则会因高度冲突加载失败。 */
#define OUG_ALTITUDE        L"404900"

#define OUG_DEVICE_NAME     L"\\Device\\PekOutGuardFilter"
#define OUG_SYMLINK_NAME    L"\\DosDevices\\PekOutGuardFilter"

/* ————— 规则表（与用户态同构，固定大小便于 METHOD_BUFFERED 直传）————— */

#define OUG_MAX_PREFIXES    16
#define OUG_MAX_PATH        260
#define OUG_MAX_EXTS        32
#define OUG_MAX_EXT_LEN     16

/* 统计（原子累加，回调里零锁） */
typedef struct _OUG_STATS {
    LONGLONG Create;
    LONGLONG Read;
    LONGLONG Write;
    LONGLONG SetInfo;
    LONGLONG Cleanup;
    /* —— M1 新增：规则判定 —— */
    LONGLONG RuleHit;        /* 命中受控规则的 Create 次数 */
    LONGLONG RuleMiss;       /* 未命中 */
    LONGLONG RuleEvalError;  /* 取不到文件名（IRQL/失败） */
    ULONG    RulesVersion;   /* 当前生效规则版本（0=未下发） */
    ULONG    PathPrefixCount;
    ULONG    ExtCount;
    WCHAR    LastHit[OUG_MAX_PATH]; /* 最近一次命中的 NT 路径（便于排错） */
} OUG_STATS, *POUG_STATS;

/* 规则集：路径前缀（NT 路径，大小写不敏感）+ 扩展名（含点，如 .DOCX） */
typedef struct _OUG_RULES {
    ULONG Version;
    ULONG PathPrefixCount;
    WCHAR PathPrefixes[OUG_MAX_PREFIXES][OUG_MAX_PATH];
    ULONG ExtCount;
    WCHAR Extensions[OUG_MAX_EXTS][OUG_MAX_EXT_LEN];
} OUG_RULES, *POUG_RULES;

static PFLT_FILTER  g_Filter = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static OUG_STATS    g_Stats;
static volatile LONG g_Enabled = 1;

/* 与用户态 `client/src/driver.rs` 的断言一一对应：
   任何一侧改了结构体，这里编译不过，Rust 那边测试也不过 —— 双保险防“协议悄悄漂移”。 */
C_ASSERT(sizeof(OUG_STATS) == 600);
C_ASSERT(sizeof(OUG_RULES) == 9356);

/* 规则表：写入时持锁，读时持锁（临界区极短，只做拷贝/比对） */
static KSPIN_LOCK  g_RulesLock;
static OUG_RULES   g_Rules;

static const UNICODE_STRING g_DeviceName  = RTL_CONSTANT_STRING(OUG_DEVICE_NAME);
static const UNICODE_STRING g_SymlinkName = RTL_CONSTANT_STRING(OUG_SYMLINK_NAME);

/* ————— IOCTL 定义（与用户态保持一致）————— */

#define OUG_DEVICE_TYPE      0x8A00

#define OUG_IOCTL_GET_STATS   CTL_CODE(OUG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_SET_ENABLED CTL_CODE(OUG_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_GET_VERSION CTL_CODE(OUG_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_SET_RULES   CTL_CODE(OUG_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OUG_IOCTL_RESET_STATS CTL_CODE(OUG_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define OUG_VERSION_MAJOR 0
#define OUG_VERSION_MINOR 2

/* ————— 匹配工具（无 CRT，手写大小写不敏感比较）————— */

static WCHAR
OugUpcase(
    _In_ WCHAR c
)
{
    return (c >= L'a' && c <= L'z') ? (WCHAR)(c - (L'a' - L'A')) : c;
}

/* path 是否以 prefix 开头（大小写不敏感） */
static BOOLEAN
OugPrefixMatch(
    _In_z_ PCWSTR Path,
    _In_z_ PCWSTR Prefix
)
{
    while (*Prefix != L'\0') {
        if (*Path == L'\0') {
            return FALSE;
        }
        if (OugUpcase(*Path) != OugUpcase(*Prefix)) {
            return FALSE;
        }
        Path++;
        Prefix++;
    }
    return TRUE;
}

/* path 是否以 suffix 结尾（大小写不敏感） */
static BOOLEAN
OugSuffixMatch(
    _In_z_ PCWSTR Path,
    _In_z_ PCWSTR Suffix
)
{
    size_t pathLen = 0;
    size_t suffixLen = 0;

    while (Path[pathLen] != L'\0') { pathLen++; }
    while (Suffix[suffixLen] != L'\0') { suffixLen++; }
    if (suffixLen == 0 || suffixLen > pathLen) {
        return FALSE;
    }

    Path += (pathLen - suffixLen);
    while (*Suffix != L'\0') {
        if (OugUpcase(*Path) != OugUpcase(*Suffix)) {
            return FALSE;
        }
        Path++;
        Suffix++;
    }
    return TRUE;
}

/* 调用方需持有 g_RulesLock */
static BOOLEAN
OugRulesMatchLocked(
    _In_z_ PCWSTR Path
)
{
    ULONG i;

    if (g_Rules.Version == 0) {
        return FALSE;   /* 规则未下发 → 一律不命中（宁可不加密） */
    }

    /* 扩展名：任意一个命中即算命中 */
    for (i = 0; i < g_Rules.ExtCount && i < OUG_MAX_EXTS; i++) {
        if (OugSuffixMatch(Path, g_Rules.Extensions[i])) {
            return TRUE;
        }
    }
    /* 路径前缀：命中即算命中（两者是“或”的关系，便于“整个目录全加密”场景） */
    for (i = 0; i < g_Rules.PathPrefixCount && i < OUG_MAX_PREFIXES; i++) {
        if (OugPrefixMatch(Path, g_Rules.PathPrefixes[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ————— 回调 ————— */

FLT_PREOP_CALLBACK_STATUS
OugPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN matched = FALSE;
    KIRQL oldIrql;

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Create);

    /* M1：只判定“是否命中受控规则”，**不做任何数据修改**。
       规则未下发时直接跳过，避免无谓的取路径开销。 */
    KeAcquireSpinLock(&g_RulesLock, &oldIrql);
    status = (g_Rules.Version == 0) ? STATUS_INVALID_DEVICE_STATE : STATUS_SUCCESS;
    KeReleaseSpinLock(&g_RulesLock, oldIrql);

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Stats.RuleMiss);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 取规范化路径；IRQL 不合适或失败都只记一次 error，绝不影响 I/O。 */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        InterlockedIncrement64(&g_Stats.RuleEvalError);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KeAcquireSpinLock(&g_RulesLock, &oldIrql);
    if (g_Rules.Version != 0 && nameInfo->Name.Buffer != NULL) {
        /* Name.Buffer 不是 NUL 结尾，这里按长度拷贝到栈上再比对。 */
        WCHAR pathBuf[OUG_MAX_PATH];
        ULONG copyChars = nameInfo->Name.Length / sizeof(WCHAR);
        if (copyChars >= OUG_MAX_PATH) {
            copyChars = OUG_MAX_PATH - 1;
        }
        RtlCopyMemory(pathBuf, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
        pathBuf[copyChars] = L'\0';

        matched = OugRulesMatchLocked(pathBuf);
        if (matched) {
            RtlStringCchCopyW(g_Stats.LastHit, OUG_MAX_PATH, pathBuf);
        }
    }
    KeReleaseSpinLock(&g_RulesLock, oldIrql);

    FltReleaseFileNameInformation(nameInfo);

    if (matched) {
        InterlockedIncrement64(&g_Stats.RuleHit);
    } else {
        InterlockedIncrement64(&g_Stats.RuleMiss);
    }

    /* M2 起：命中后在这里建立每文件上下文（密钥）并在 Read/Write 上加解密。 */
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

    case OUG_IOCTL_SET_RULES:
    {
        /* 规则表整块覆盖：版本号必须递增（用户态负责），驱动只信任内容。 */
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(OUG_RULES)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        POUG_RULES incoming = (POUG_RULES)buffer;
        ULONG newVersion;
        KIRQL oldIrql;

        /* 参数校验：越界的计数一律拒绝，避免匹配时越界读 */
        if (incoming->PathPrefixCount > OUG_MAX_PREFIXES ||
            incoming->ExtCount > OUG_MAX_EXTS ||
            incoming->Version == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        newVersion = incoming->Version;

        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
        RtlCopyMemory(&g_Rules, incoming, sizeof(OUG_RULES));
        /* 强制 NUL 结尾，防止用户态传进来的字符串没有结尾 */
        for (ULONG i = 0; i < OUG_MAX_PREFIXES; i++) {
            g_Rules.PathPrefixes[i][OUG_MAX_PATH - 1] = L'\0';
        }
        for (ULONG i = 0; i < OUG_MAX_EXTS; i++) {
            g_Rules.Extensions[i][OUG_MAX_EXT_LEN - 1] = L'\0';
        }
        g_Stats.RulesVersion = newVersion;
        g_Stats.PathPrefixCount = g_Rules.PathPrefixCount;
        g_Stats.ExtCount = g_Rules.ExtCount;
        KeReleaseSpinLock(&g_RulesLock, oldIrql);

        status = STATUS_SUCCESS;
        outLen = 0;
        DbgPrint("[PekOutGuard] rules updated: v=%lu prefixes=%lu exts=%lu\n",
                 newVersion, incoming->PathPrefixCount, incoming->ExtCount);
        break;
    }

    case OUG_IOCTL_RESET_STATS:
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
        g_Stats.Create = 0;
        g_Stats.Read = 0;
        g_Stats.Write = 0;
        g_Stats.SetInfo = 0;
        g_Stats.Cleanup = 0;
        g_Stats.RuleHit = 0;
        g_Stats.RuleMiss = 0;
        g_Stats.RuleEvalError = 0;
        g_Stats.LastHit[0] = L'\0';
        KeReleaseSpinLock(&g_RulesLock, oldIrql);
        status = STATUS_SUCCESS;
        outLen = 0;
        break;
    }

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

    KeInitializeSpinLock(&g_RulesLock);
    RtlZeroMemory(&g_Rules, sizeof(g_Rules));
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));

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
