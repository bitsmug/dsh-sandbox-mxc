/**
 * dsh-sandbox-mxc · lib/index.js —— 用 MXC（Microsoft eXecution Containers）实现 DSH 的进程沙箱接缝。
 *
 * ── 为什么这样做 ────────────────────────────────────────────────────────────
 * DSH 的沙箱接缝是**纯 argv 包装**：`SandboxProvider.confine(argv, policy, signal)` 返回
 * `ConfinedArgv{ argv, enforcement, denialSignatures, runnerFailureRules }`（见
 * `@deepseek-ai/dsh-sandbox` 的 `lib/types/index.d.ts`）。而 MXC 的命令行执行器形状刚好吻合：
 *
 *     wxc-exec.exe [OPTIONS] [CONFIG_PATH] [-- <COMMAND>...]
 *
 * ⇒ 本 provider 只需返回 `[wxcExec, '--config-base64', <策略JSON base64>, '--', ...原 argv]`：
 *   · **不经过 `@microsoft/mxc-sdk` 的原生 stdio 绑定** ⇒ 不受"Windows 原生 stdio 需要
 *     Node ≥ 24.21.0（24 线）/ ≥ 26.8.0"这条硬限制（DSH 自带的是 v24.20.0，实测走 SDK 的
 *     `spawn()` 会抛 `MxcError … backend_unavailable`）；
 *   · **只用一个运行时依赖**（`@microsoft/mxc-sdk`，为拿到 `wxc-exec.exe`）：但**不 import 它**，
 *     只用 `require.resolve` 推导可执行文件的位置 ⇒ 既拿到执行器，又不碰原生绑定；
 *   · **不 patch 内核**：与 `dsh-sandbox-local` 并列的另一个 provider 实现。
 *
 * ── 策略语义只有一处实现 ────────────────────────────────────────────────────
 * 读写根由 `@deepseek-ai/dsh-sandbox` 导出的 `writableRoots(policy)` / `canonicalPath(path)` 决定
 * （`workspace-write` = 工作区根 + 平台临时区；`read-only` = 空），本模块**不重新解释** mode 的含义。
 *
 * ── 安全默认（口径来自真机实测；结论与证据见 README 的 Security posture 一节）──
 * · `ui.disable` 必须为 `false`（否则容器拦掉 Win32k，`node.exe`/`pwsh` 直接
 *   `STATUS_DLL_INIT_FAILED (0xC0000142)`）；
 * · 但 `clipboard` 与 `injection` **显式钉死为 `none`/`false`** —— 实测剪贴板是**隔离**的
 *   （宿主标记容器读不到、容器写不进宿主），且拦截表现为**静默 no-op 而非报错**；
 * · 文件面默认拒绝（白名单之外**连读都拒**）⇒ 调用方必须显式给出需要的读根。
 */
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import {
  canonicalPath,
  SandboxProvider,
  SandboxUnavailableError,
  writableRoots,
} from '@deepseek-ai/dsh-sandbox';

/** MXC 的 wire 契约版本（`@microsoft/mxc-sdk/dist/v1/contract-version.js` 导出的 SDK_CONTRACT_VERSION）。 */
export const MXC_CONTRACT_VERSION = '1.0.0';

/** 容器内**必须**放开 Win32k（跑 node/pwsh 的前提），但剪贴板与注入保持关闭。 */
export const DEFAULT_UI = Object.freeze({ disable: false, clipboard: 'none', injection: false });

/** BaseContainer 的 UI 隔离默认值（关掉桌面系统控制与 IME）。 */
export const DEFAULT_PROCESS_CONTAINER_UI = Object.freeze({
  isolation: 'container',
  desktopSystemControl: false,
  systemSettings: 'none',
  ime: false,
});

/** 一个容器 id 只用于日志/诊断，随机后缀避免并发调用互相覆盖。 */
export function defaultContainerId(prefix = 'dsh-mxc') {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * 归一化插件配置（手写校验，不引入 schemastery ⇒ 保持零运行时依赖）。
 * @param {any} raw 插件行上的 `config`
 */
export function normalizeConfig(raw) {
  const cfg = raw ?? {};
  const strings = (value) => (Array.isArray(value) ? value.filter((x) => typeof x === 'string' && x !== '') : []);
  return {
    /** `wxc-exec` 的绝对路径；留空则尝试从 `@microsoft/mxc-sdk` 推导（见 resolveWxcExecutable）。 */
    wxcExecPath: typeof cfg.wxcExecPath === 'string' ? cfg.wxcExecPath.trim() : '',
    /** 除工作区之外还要**只读**开放的根（例如工具链目录）。 */
    readonlyPaths: strings(cfg.readonlyPaths),
    /** 除 writableRoots(policy) 之外额外**可写**的根。 */
    extraWritablePaths: strings(cfg.extraWritablePaths),
    /** 一律拒绝的根（MXC `filesystem.deniedPaths`）。 */
    deniedPaths: strings(cfg.deniedPaths),
    /** 网络策略：不传则 MXC 默认 block（实测 default_policy=block）。 */
    network: cfg.network && typeof cfg.network === 'object' ? cfg.network : undefined,
    /** 单次执行超时（毫秒）；0/缺省 = 不设（交给调用方的 signal）。 */
    timeoutMs: Number.isFinite(cfg.timeoutMs) ? Number(cfg.timeoutMs) : 0,
    /** 诊断用容器名前缀。 */
    containerIdPrefix: typeof cfg.containerIdPrefix === 'string' && cfg.containerIdPrefix !== '' ? cfg.containerIdPrefix : 'dsh-mxc',
  };
}

/**
 * 推导 `wxc-exec` 的位置：显式配置 → 环境变量 → `@microsoft/mxc-sdk` 包内路径。
 * **不写死任何机器路径**（遵循工作区纪律）。
 * @param {ReturnType<typeof normalizeConfig>} cfg
 * @returns {string} 可用的绝对路径
 * @throws {Error} 都拿不到时抛错（调用方需 fail-closed）
 */
export function resolveWxcExecutable(cfg) {
  const candidates = [];
  if (cfg.wxcExecPath !== '') candidates.push(cfg.wxcExecPath);
  const fromEnv = process.env.DSH_MXC_WXC;
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') candidates.push(fromEnv.trim());
  try {
    const require = createRequire(import.meta.url);
    const pkgPath = require.resolve('@microsoft/mxc-sdk/package.json');
    candidates.push(join(dirname(pkgPath), 'bin', 'x64', 'wxc-exec.exe'));
  } catch { /* 没装 SDK：忽略这条候选 */ }
  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) return candidate;
  }
  throw new Error(
    'MXC 执行器 wxc-exec.exe 不可用：请给插件 config.wxcExecPath，或设环境变量 DSH_MXC_WXC，'
    + `或让 @microsoft/mxc-sdk 可解析。已尝试：${candidates.length === 0 ? '(无候选)' : candidates.join(' ; ')}`,
  );
}

/**
 * 由 DSH 策略 + 插件配置生成 MXC 的容器配置对象（纯函数，便于单测）。
 * @param {{ mode: string, workspaceRoot?: string }} policy
 * @param {ReturnType<typeof normalizeConfig>} cfg
 */
export function buildPolicyConfig(policy, cfg, containerId = defaultContainerId(cfg.containerIdPrefix)) {
  const writable = [...writableRoots(policy), ...cfg.extraWritablePaths].map(canonicalPath);
  // ★ 工作区必须始终**可读**：`read-only` 下 writableRoots 返回空，若不显式给只读根，
  //   容器连工作区里的文件都读不到（实测白名单之外连读都拒）⇒ 该档位会变得毫无用处。
  const readonly = [...cfg.readonlyPaths];
  if (policy.workspaceRoot !== undefined && policy.workspaceRoot !== '') {
    const workspaceCanonical = canonicalPath(policy.workspaceRoot);
    if (!writable.includes(workspaceCanonical)) readonly.push(policy.workspaceRoot);
  }
  const config = {
    version: MXC_CONTRACT_VERSION,
    containerId,
    lifecycle: { destroyOnExit: true, preservePolicy: false },
    // `-- <COMMAND>` 会覆盖 commandLine；这里给一个非空占位（wire 契约要求 process.commandLine 非空）
    process: { commandLine: 'cmd /c exit 0', timeout: cfg.timeoutMs },
    filesystem: {
      readwritePaths: [...new Set(writable)],
      readonlyPaths: [...new Set(readonly.map(canonicalPath))],
      deniedPaths: [...new Set(cfg.deniedPaths.map(canonicalPath))],
    },
    ui: { ...DEFAULT_UI },
    processContainer: { capabilities: [], ui: { ...DEFAULT_PROCESS_CONTAINER_UI } },
  };
  if (cfg.network !== undefined) config.network = cfg.network;
  return config;
}

/**
 * 把调用方 argv 包成 MXC 执行器 argv（纯函数）。
 * @param {readonly string[]} argv 调用方即将 spawn 的完整 argv
 * @param {{ mode: string, workspaceRoot?: string }} policy
 * @param {ReturnType<typeof normalizeConfig>} cfg
 * @param {string} wxcExecPath
 */
export function buildRunnerArgv(argv, policy, cfg, wxcExecPath) {
  const config = buildPolicyConfig(policy, cfg);
  const encoded = Buffer.from(JSON.stringify(config), 'utf8').toString('base64');
  return [wxcExecPath, '--config-base64', encoded, '--', ...argv];
}

/**
 * DSH 的进程沙箱提供者（服务名 `sandbox`，由基类构造时注册）。
 */
export class MxcSandboxProvider extends SandboxProvider {
  constructor(ctx, config) {
    super(ctx);
    this.config = normalizeConfig(config);
  }

  /**
   * 把 argv 包进 MXC 容器。
   * @param {readonly string[]} argv
   * @param {{ mode: string, workspaceRoot?: string }} policy
   * @param {AbortSignal} [signal]
   */
  async confine(argv, policy, signal) {
    if (signal?.aborted) throw new SandboxUnavailableError(policy.mode, '调用已取消');
    let wxcExecPath;
    try {
      wxcExecPath = resolveWxcExecutable(this.config);
    } catch (error) {
      // fail-closed：拿不到执行器就拒绝运行，绝不静默放行
      throw new SandboxUnavailableError(policy.mode, error.message);
    }
    return {
      argv: buildRunnerArgv(argv, policy, this.config, wxcExecPath),
      // MXC 用路径白名单/黑名单表达文件效果（实测白名单外连读都拒）⇒ 视为完整执行
      enforcement: 'full',
      // MXC 的拒绝在容器内表现为宿主文件 API 的常规拒绝文本（Node/PowerShell 同源）
      denialSignatures: ['Access is denied', 'Access to the path', 'EPERM', 'EACCES'],
      // runner 自身的失败证据待 P2 用真机用例收窄，先不给规则（避免误报）
      runnerFailureRules: [],
    };
  }
}

export default MxcSandboxProvider;
