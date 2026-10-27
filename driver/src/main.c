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
/* IoCreateDeviceSecure + SDDL：控制设备必须限制为 SYSTEM/管理员可访问 */
#include <wdmsec.h>
/* BCrypt SHA-256：校验 ADS 元数据的校验和（防篗改） */
#include <bcrypt.h>

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
    /* —— M2a 新增：ADS 元数据探测（**只读，不改任何数据**）—— */
    LONGLONG AdsHit;         /* 读到有效加密标记（文件已加密） */
    LONGLONG AdsAbsent;      /* 没有标记（未加密 / 标记未置加密位） */
    LONGLONG AdsBroken;      /* 有流但魔数/版本/长度不对（损坏） */
    LONGLONG AdsError;       /* 打不开/读失败（权限异常、文件被删等真实问题） */
    UCHAR    LastAdsFileId[8]; /* 最近一次读到的 file_id（XTS tweak 基值） */
    LONGLONG AdsSkipped;     /* 未探测：IRQL 不合适（分页 I/O）等不可做的情形，**不是错误** */
    LONGLONG AdsTampered;    /* 魔数/版本合法但**校验和对不上**：标记被篡改或写坏了 */
} OUG_STATS, *POUG_STATS;

/* 规则集：路径前缀（NT 路径，大小写不敏感）+ 扩展名（含点，如 .DOCX） */
typedef struct _OUG_RULES {
    ULONG Version;
    ULONG PathPrefixCount;
    WCHAR PathPrefixes[OUG_MAX_PREFIXES][OUG_MAX_PATH];
    ULONG ExtCount;
    WCHAR Extensions[OUG_MAX_EXTS][OUG_MAX_EXT_LEN];
} OUG_RULES, *POUG_RULES;

/* 只读视图：双缓冲的读侧只用它，编译器会挡住"读侧误改规则" */
typedef const OUG_RULES *PCOUG_RULES;

static PFLT_FILTER  g_Filter = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static OUG_STATS    g_Stats;
static volatile LONG g_Enabled = 1;

/* SHA-256 算法句柄：在 DriverEntry 打开一次，全局复用。
   每次探测都 Open/Cose 算法提供程序太贵（分配 + 注册表访问）。
   BCrypt 算法句柄本身是线程安全的，并发时只需各自 CreateHash。 */
static BCRYPT_ALG_HANDLE g_Sha256Alg = NULL;

/* 与用户态 `client/src/driver.rs` 的断言一一对应：
   任何一侧改了结构体，这里编译不过，Rust 那边测试也不过 —— 双保险防“协议悄悄漂移”。 */
C_ASSERT(sizeof(OUG_STATS) == 656);
C_ASSERT(sizeof(OUG_RULES) == 9356);

/* ————— M2a：NTFS 备用数据流（ADS）元数据（与 core::meta 严格一致）————— */

#define OUG_META_STREAM          L":oug"   /* 元数据流后缀（主文件大小不变） */
#define OUG_META_STREAM_CHARS    4          /* L":oug" 的字符数 */
#define OUG_META_LEN             32         /* 元数据固定 32 字节 */
#define OUG_META_VERSION         1          /* 格式版本 */
#define OUG_META_FLAG_ENCRYPTED  0x01       /* 位 0 = 已加密 */
#define OUG_META_OFF_FLAGS       5          /* flags 字节偏移 */
#define OUG_META_OFF_FILEID      8          /* file_id 8 字节偏移 */
#define OUG_META_OFF_CHECKSUM    24         /* 校验和 8 字节偏移：SHA-256(bytes[0..24])[0..8] */
#define OUG_META_CHECKSUM_BYTES  8          /* 只存 SHA-256 前 8 字节 */
#define OUG_SHA256_LEN           32

/* 规则表：**双缓冲无锁读**。

   原实现是“写时持锁 + 回调里持锁做几十次字符串比较”：最坏 48 条规则 × 260 字符，
   在 DISPATCH_LEVEL 自旋锁内跑几微秒 = 其他 CPU 全部自旋等待，属于性能/稳定性隐患。

   现改为：两块静态缓冲 + 一个原子索引。
     · 写（IOCTL，很罕见）：先填非当前块 → 全屏障后 `InterlockedExchange` 切换索引；
     · 读（PreCreate，极热）：一次原子读拿到索引，无锁遍历。
   切换瞬间可能有单个 I/O 用到上一版规则——与“规则滚动更新”语义一致，可接受；
   旧缓冲是静态内存、永不释放，所以不存在 use-after-free。*/
static OUG_RULES      g_RulesBuf[2];
static volatile LONG  g_RulesIndex = 0;

#define OUG_RULES_CURRENT() \
    (&g_RulesBuf[InterlockedCompareExchange(&g_RulesIndex, 0, 0) & 1])

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
#define OUG_VERSION_MINOR 3

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

/* 纯函数，无锁：调用方传入当前规则块（双缓冲保证生命周期） */
static BOOLEAN
OugRulesMatch(
    _In_ PCOUG_RULES Rules,
    _In_z_ PCWSTR Path
)
{
    ULONG i;

    if (Rules->Version == 0) {
        return FALSE;   /* 规则未下发 → 一律不命中（宁可不加密） */
    }

    /* 扩展名：任意一个命中即算命中 */
    for (i = 0; i < Rules->ExtCount && i < OUG_MAX_EXTS; i++) {
        if (OugSuffixMatch(Path, Rules->Extensions[i])) {
            return TRUE;
        }
    }
    /* 路径前缀：命中即算命中（两者是“或”的关系，便于“整个目录全加密”场景） */
    for (i = 0; i < Rules->PathPrefixCount && i < OUG_MAX_PREFIXES; i++) {
        if (OugPrefixMatch(Path, Rules->PathPrefixes[i])) {
            return TRUE;
        }
    }
    return FALSE;
}
/* ————— 元数据校验和验证（防篗改）—————

   为什么内核必须自己验：
       如果攻击者把 ADS 里的 file_id 改掉、而魔数和版本仍然合法，
       驱动就会拿错误的 tweak 去解密 —— 得到一堆乱码，
       应用若把乱码回写，文件就真坏了（不可逆）。

   算法与 core/src/meta.rs 完全一致：checksum = SHA-256(bytes[0..24])[0..8]

   返回 TRUE 仅当校验和匹配。任何失败（含 BCrypt 出错）都返回 FALSE ——
   **存疑不信**：宁可当作“未加密/不可用”，也不能用可疑的 file_id 去加解密。*/
static BOOLEAN
OugMetaChecksumValid(
    _In_reads_(OUG_META_LEN) const UCHAR* Meta
)
{
    BCRYPT_HASH_HANDLE hash = NULL;
    UCHAR digest[OUG_SHA256_LEN];
    NTSTATUS status;
    BOOLEAN ok = FALSE;

    if (g_Sha256Alg == NULL) {
        return FALSE;   /* 算法不可用：无法验证就不信 */
    }

    status = BCryptCreateHash(g_Sha256Alg, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = BCryptHashData(hash, (PUCHAR)Meta, OUG_META_OFF_CHECKSUM, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    }
    BCryptDestroyHash(hash);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    /* 定长比较普通 memcmp 即可（长度不泄露信息，不存在时序攻击面） */
    ok = (RtlCompareMemory(digest, Meta + OUG_META_OFF_CHECKSUM, OUG_META_CHECKSUM_BYTES)
          == OUG_META_CHECKSUM_BYTES);

    RtlSecureZeroMemory(digest, sizeof(digest));
    return ok;
}

/* ————— M2a：ADS 元数据探测（**只读**，不改任何数据）—————

   目的：命中受控规则的文件，驱动需要知道它"到底加密了没有"以及"它的 file_id 是什么"。
       file_id 是 XTS tweak 的基值，M2b 的 Read/Write 加解密就靠它。
       这些信息存在 NTFS 备用数据流 `file:oug` 里（32 字节，主文件大小不变）。

   安全约束（每一条都不能违反）：
      · 只打开 `FILE_READ_DATA`，**不写、不删、不改属性**；
      · 任何失败（权限/IRQL/路径过长/文件被独占）只计数，**绝不影响原始 I/O**；
      · 路径长度不够就跳过，**绝不把截断的路径拿去打开**（会打开错的文件）；
      · **递归保护靠 FltCreateFileEx2 的 Instance 参数**：把本实例传进去，I/O 就从
        该实例**下方**发起，根本不会再进入我们自己的 PreCreate。比 IoSetTopLevelIrp
        干净（WDK 26100 已移除 FLT_TOP_LEVEL_IRP 常量），也不会干扰其他 filter。
        Instance 为空时直接放弃探测 —— 宁可不探测，也不要冒无限递归的风险。

   性能：每个"命中规则且带有效文件名的 Create"多一次 Create+Read+Close。
       实测口径见 `driver status` 的 Ads* 计数；若开销偏高，M2b 加 stream handle
       上下文缓存（同一文件多次 Create 只探测一次）。
*/
static VOID
OugProbeMetaAds(
    _In_ PFLT_FILTER Filter,
    _In_ PFLT_INSTANCE Instance,
    _In_reads_(PathChars) PCWSTR NtPath,
    _In_ ULONG PathChars
)
{
    NTSTATUS status;
    WCHAR streamPath[OUG_MAX_PATH + OUG_META_STREAM_CHARS + 2];
    UNICODE_STRING streamName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE handle = NULL;
    PFILE_OBJECT fileObject = NULL;
    UCHAR meta[OUG_META_LEN];
    LARGE_INTEGER offset;
    ULONG totalChars;

    /* FltCreateFile / ZwReadFile 都必须在 PASSIVE_LEVEL 发起。
       PreCreate 偶尔会在 APC_LEVEL 上（分页 I/O 等）—— 那不是错误，
       只是这次探测做不了，记 AdsSkipped（不要冒充 AdsError 误导运维）。 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        InterlockedIncrement64(&g_Stats.AdsSkipped);
        return;
    }

    /* 没有实例就无法“从本实例下方发起”，递归风险不可控 → 放弃 */
    if (Instance == NULL || Filter == NULL) {
        InterlockedIncrement64(&g_Stats.AdsError);
        return;
    }

    if (PathChars == 0 ||
        PathChars + OUG_META_STREAM_CHARS + 1 > RTL_NUMBER_OF(streamPath)) {
        /* 路径过长：不截断、不猜，直接放弃（截断会打开到别的文件） */
        InterlockedIncrement64(&g_Stats.AdsError);
        return;
    }

    RtlCopyMemory(streamPath, NtPath, PathChars * sizeof(WCHAR));
    RtlCopyMemory(streamPath + PathChars, OUG_META_STREAM, OUG_META_STREAM_CHARS * sizeof(WCHAR));
    totalChars = PathChars + OUG_META_STREAM_CHARS;
    streamPath[totalChars] = L'\0';

    RtlInitUnicodeString(&streamName, streamPath);
    InitializeObjectAttributes(
        &objectAttributes,
        &streamName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = FltCreateFileEx2(
        Filter,
        Instance,
        &handle,
        &fileObject,
        FILE_READ_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,                                   /* AllocationSize */
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,                                   /* EaBuffer */
        0,                                      /* EaLength */
        IO_IGNORE_SHARE_ACCESS_CHECK,
        NULL);                                  /* DriverContext */

    if (!NT_SUCCESS(status)) {
        if (fileObject != NULL) {
            ObDereferenceObject(fileObject);
            fileObject = NULL;
        }
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) {
            /* 没有标记流 —— 最常见的情形（未加密文件） */
            InterlockedIncrement64(&g_Stats.AdsAbsent);
        } else if (status == STATUS_REPARSE_POINT_ENCOUNTERED ||
                   status == STATUS_DELETE_PENDING ||
                   status == STATUS_FILE_DELETED) {
            /* 文件正在被删除/重定向：不是错误，也不该算损坏 */
            InterlockedIncrement64(&g_Stats.AdsAbsent);
        } else {
            InterlockedIncrement64(&g_Stats.AdsError);
        }
        return;
    }

    /* 同步句柄：读 32 字节。只读，绝不写。 */
    offset.QuadPart = 0;
    RtlZeroMemory(meta, sizeof(meta));
    status = ZwReadFile(
        handle, NULL, NULL, NULL, &ioStatus, meta, OUG_META_LEN, &offset, NULL);

    FltClose(handle);
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
        fileObject = NULL;
    }

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Stats.AdsError);
        return;
    }

    /* 长度不足 / 不是我们的魔数 / 版本不认 —— 都算"标记损坏"，绝不猜 */
    if (ioStatus.Information != OUG_META_LEN ||
        meta[0] != 'O' || meta[1] != 'G' || meta[2] != 'M' || meta[3] != '1' ||
        meta[4] != OUG_META_VERSION) {
        InterlockedIncrement64(&g_Stats.AdsBroken);
        return;
    }
    /* 校验和：魔数合法不等于内容可信 —— 必须验 SHA-256，否则可以用错的 file_id 解密。 */
    if (!OugMetaChecksumValid(meta)) {
        InterlockedIncrement64(&g_Stats.AdsTampered);
        return;
    }
    if ((meta[OUG_META_OFF_FLAGS] & OUG_META_FLAG_ENCRYPTED) == 0) {
        /* 标记在但未置加密位：视为未加密（加密中途失败的残留由用户态清理） */
        InterlockedIncrement64(&g_Stats.AdsAbsent);
        return;
    }

    /* 有效加密标记：记下 file_id 供 M2b 使用 */
    RtlCopyMemory(g_Stats.LastAdsFileId, meta + OUG_META_OFF_FILEID, sizeof(g_Stats.LastAdsFileId));
    InterlockedIncrement64(&g_Stats.AdsHit);
}
/* ————— 回调 ————— */

FLT_PREOP_CALLBACK_STATUS
OugPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PCOUG_RULES rules;
    NTSTATUS status;
    BOOLEAN matched = FALSE;
    WCHAR pathBuf[OUG_MAX_PATH];
    ULONG pathChars = 0;
    BOOLEAN pathUsable = FALSE;

    if (InterlockedCompareExchange(&g_Enabled, 1, 1) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement64(&g_Stats.Create);

    /* M1：只判定"是否命中受控规则"，**不做任何数据修改**。
       规则未下发时直接跳过，避免无谓的取路径开销。
       双缓冲：这里只是一次原子读，**不加锁**（见 g_RulesBuf 的说明）。 */
    rules = OUG_RULES_CURRENT();
    if (rules->Version == 0) {
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

    if (nameInfo->Name.Buffer != NULL) {
        /* Name.Buffer 不是 NUL 结尾，这里按长度拷贝到栈上再比对。 */
        ULONG copyChars = nameInfo->Name.Length / sizeof(WCHAR);
        if (copyChars >= OUG_MAX_PATH) {
            /* 路径超长：**不做截断匹配**。截断后的路径可能命中另一条规则，
               把不该加密的文件判成受控（或反之）—— 属于安全性错误，
               宁可判为"不命中"。 */
            InterlockedIncrement64(&g_Stats.RuleEvalError);
            copyChars = 0;
        }
        if (copyChars > 0) {
            RtlCopyMemory(pathBuf, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
            pathBuf[copyChars] = L'\0';
            pathChars = copyChars;
            pathUsable = TRUE;

            matched = OugRulesMatch(rules, pathBuf);
            if (matched) {
                RtlStringCchCopyW(g_Stats.LastHit, OUG_MAX_PATH, pathBuf);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);

    if (matched) {
        InterlockedIncrement64(&g_Stats.RuleHit);
    } else {
        InterlockedIncrement64(&g_Stats.RuleMiss);
    }

    /* M2a：命中规则 → 读它的加密标记（**只读**，为 M2b 的加解密做准备）。
       放在释放 nameInfo 之后：探测会发起新的 Create，不宜在持有任何资源时做。 */
    if (matched && pathUsable) {
        OugProbeMetaAds(g_Filter, FltObjects->Instance, pathBuf, pathChars);
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
        POUG_RULES target;
        LONG next;
        ULONG i;

        /* 参数校验：越界的计数一律拒绝，避免匹配时越界读 */
        if (incoming->PathPrefixCount > OUG_MAX_PREFIXES ||
            incoming->ExtCount > OUG_MAX_EXTS ||
            incoming->Version == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* 字符串必须以 NUL 结尾且**在有效范围内**。
           只强行写最后一个字节为 NUL 是不够的：那等于把超长字符串悄悄截断，
           截断后的路径做前缀匹配可能命中另一条规则（安全性错误）→ 整包拒绝。 */
        for (i = 0; i < OUG_MAX_PREFIXES; i++) {
            BOOLEAN terminated = FALSE;
            ULONG j;
            for (j = 0; j < OUG_MAX_PATH; j++) {
                if (incoming->PathPrefixes[i][j] == L'\0') {
                    terminated = TRUE;
                    break;
                }
            }
            if (!terminated) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        if (!NT_SUCCESS(status)) {
            break;
        }
        for (i = 0; i < OUG_MAX_EXTS; i++) {
            BOOLEAN terminated = FALSE;
            ULONG j;
            for (j = 0; j < OUG_MAX_EXT_LEN; j++) {
                if (incoming->Extensions[i][j] == L'\0') {
                    terminated = TRUE;
                    break;
                }
            }
            if (!terminated) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        if (!NT_SUCCESS(status)) {
            break;
        }

        /* 双缓冲：填非当前块 → 全屏障切换索引（InterlockedExchange 在 x86 上带全屏障） */
        next = 1 - (InterlockedCompareExchange(&g_RulesIndex, 0, 0) & 1);
        target = &g_RulesBuf[next];
        RtlCopyMemory(target, incoming, sizeof(OUG_RULES));
        InterlockedExchange(&g_RulesIndex, next);

        g_Stats.RulesVersion = target->Version;
        g_Stats.PathPrefixCount = target->PathPrefixCount;
        g_Stats.ExtCount = target->ExtCount;

        status = STATUS_SUCCESS;
        outLen = 0;
        DbgPrint("[PekOutGuard] rules updated: v=%lu prefixes=%lu exts=%lu\n",
                 target->Version, target->PathPrefixCount, target->ExtCount);
        break;
    }

    case OUG_IOCTL_RESET_STATS:
    {
        /* 64 位对齐字段的写入在 x64 上是原子的；统计是"快照"语义，
           偶尔与并发 I/O 撞车导致某项少清一次可接受，不值得为它加锁。 */
        g_Stats.Create = 0;
        g_Stats.Read = 0;
        g_Stats.Write = 0;
        g_Stats.SetInfo = 0;
        g_Stats.Cleanup = 0;
        g_Stats.RuleHit = 0;
        g_Stats.RuleMiss = 0;
        g_Stats.RuleEvalError = 0;
        g_Stats.LastHit[0] = L'\0';
        /* M2a：这五项必须一起清，否则清零后统计看起来"没生效" */
        g_Stats.AdsHit = 0;
        g_Stats.AdsAbsent = 0;
        g_Stats.AdsBroken = 0;
        g_Stats.AdsError = 0;
        g_Stats.AdsSkipped = 0;
        g_Stats.AdsTampered = 0;
        RtlZeroMemory(g_Stats.LastAdsFileId, sizeof(g_Stats.LastAdsFileId));
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
    /* **安全关键**：控制设备能下发规则、清规则、关判定、读文件路径统计。
       用 IoCreateDevice 时设备没有显式 DACL（默认允许 Everyone），
       结果是任何普通用户都能 `driver rules --clear` 把防泄漏关掉、
       还能读到最近命中的文件路径 —— 对 DLP 产品等于形同虚设。

       SDDL：D:P(A;;GA;;;SY)(A;;GA;;;BA)
         D:P           DACL，受保护（不继承父目录的宽松权限）
         A;;GA;;;SY   允许 SYSTEM 完全访问
         A;;GA;;;BA   允许 Administrators 完全访问
       其余身份一律无权打开。 */
    static const UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,
        0,
        (PUNICODE_STRING)&g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        NULL,                      /* DeviceClassGuid：不指定具体安装类 */
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PekOutGuard] IoCreateDeviceSecure failed: 0x%08X\n", status);
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
    if (g_Sha256Alg != NULL) {
        BCryptCloseAlgorithmProvider(g_Sha256Alg, 0);
        g_Sha256Alg = NULL;
    }
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

    /* 规则双缓冲：两块都清零 + 索引归零（Version=0 ⇒ 未下发 ⇒ 一律不命中） */
    RtlZeroMemory(g_RulesBuf, sizeof(g_RulesBuf));
    InterlockedExchange(&g_RulesIndex, 0);
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));

    /* 打开 SHA-256 算法提供程序（全局一次）。
       打不开就**拒绝加载**：验不了校验和就无法安全地使用 file_id，
       带着这个缺陷运行等于给数据损坏留了口子。 */
    status = BCryptOpenAlgorithmProvider(&g_Sha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[PekOutGuard] BCryptOpenAlgorithmProvider(SHA-256) failed 0x%08X —— 拒绝加载\n", status);
        g_Sha256Alg = NULL;
        return status;
    }
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
