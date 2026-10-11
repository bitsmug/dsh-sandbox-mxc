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
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import {
  canonicalPath,
  SandboxProvider,
  SandboxUnavailableError,
  writableRoots,
} from '@deepseek-ai/dsh-sandbox';

/**
 * ── 容器内命名管道不可用 ⇒ Node 层补偿 shim ────────────────────────────────────
 * 真机实测（同一台机器、同一个 MXC 容器内）：
 *   · spawnSync('cmd.exe', ['/c','echo','hi'], { encoding: 'utf8', timeout: 300 }) **永不返回**，
 *     timeout / killSignal 都不生效；同一个容器里 stdio: ['ignore', fd, fd]（文件句柄）/
 *     inherit / ignore 都在 6–10ms 内正常返回 ✓；
 *   · 根因是令牌级限制：容器内建不了命名管道（.NET NamedPipeServerStream 报
 *     Access to the path is denied；net.listen 报 EADDRINUSE），libuv 改不动。
 * ⇒ 注入一个 --import 预载 shim：把**同步** API 透明改成文件句柄捕获，把**异步** API
 *   （容器里一定会挂）立刻变成可读错误。源码内联在 data:text/javascript, 里，不落任何文件。
 *
 * 覆盖范围与代价：
 *   · spawnSync / execFileSync / execSync 都换了实现 —— exec*Sync 必须重写：Node 内部实现
 *     不经过被覆写的 cp.spawnSync 导出，只覆写导出盖不住它们；
 *   · encoding 缺省与 Node 一致：三者都是 'buffer'（返回 Buffer）；
 *   · maxBuffer（默认 1MiB）不再生效 —— 输出走文件，没有管道缓冲上限。
 *
 * ★ 尺寸敏感：这份源码会经 NODE_OPTIONS → 配置 JSON → --config-base64 进**命令行**
 *   （Windows CreateProcess 上限 ≈32767 字符）。所以只有本注释写在命令行之外，
 *   shim 内部的注释必须保持极短。补丁脚本会对编码后的长度做硬断言。
 * 详见 README 的 Container environment 一节（含实测矩阵）。
 */
export const NOPIPE_SHIM_SOURCE = [
  "// dsh-sandbox-mxc · 容器内 node 预载 shim（插件经 NODE_OPTIONS=--import data:text/javascript,... 注入）",
  "// 容器令牌建不了命名管道 ⇒ libuv 的管道捕获会永久挂住，且 timeout / killSignal 都不生效。",
  "// 对策：同步 API 改用临时文件句柄；异步 API（spawn/exec/execFile/fork）立即抛可读错误。",
  "import cp from 'node:child_process';",
  "import {",
  "  closeSync,",
  "  mkdtempSync,",
  "  openSync,",
  "  readFileSync,",
  "  rmSync,",
  "  unlinkSync,",
  "  writeFileSync,",
  "} from 'node:fs';",
  "import { tmpdir } from 'node:os';",
  "import { join } from 'node:path';",
  "",
  "const LF = String.fromCharCode(10);",
  "",
  "if (globalThis.__dshSandboxMxcNoPipeShim !== true) {",
  "  globalThis.__dshSandboxMxcNoPipeShim = true;",
  "  const realSpawnSync = cp.spawnSync;",
  "  let seq = 0;",
  "",
  "  const isPipeSlot = (slot) => slot === undefined || slot === null || slot === 'pipe';",
  "",
  "  const normalizeStdio = (stdio) => {",
  "    if (stdio === undefined || stdio === null) return ['pipe', 'pipe', 'pipe'];",
  "    if (typeof stdio === 'string') return [stdio, stdio, stdio];",
  "    if (!Array.isArray(stdio)) return null;",
  "    const head = stdio.slice(0, 3);",
  "    while (head.length < 3) head.push('pipe');",
  "    return head;",
  "  };",
  "",
  "  // 复刻 Node 的参数归一化：args 是数组就用它；是对象就当 options；别的形状交回原生实现去抛错。",
  "  const splitArgs = (args, options) => {",
  "    if (Array.isArray(args)) return { args, options: options === undefined || options === null ? {} : options };",
  "    if (args === undefined || args === null) return { args: [], options: options === undefined || options === null ? {} : options };",
  "    if (typeof args === 'object') return { args: [], options: args };",
  "    return null;",
  "  };",
  "",
  "  const spawnSyncWithFileStdio = (file, args, options) => {",
  "    const split = splitArgs(args, options);",
  "    if (split === null) return realSpawnSync.call(cp, file, args, options);",
  "    const opts = split.options;",
  "    const cmdArgs = split.args;",
  "    if (opts === null || typeof opts !== 'object') return realSpawnSync.call(cp, file, cmdArgs, opts);",
  "    const stdio = normalizeStdio(opts.stdio);",
  "    if (stdio === null) return realSpawnSync.call(cp, file, cmdArgs, opts);",
  "    const captured = [];",
  "    for (let i = 0; i < 3; i += 1) {",
  "      if (i === 0 && opts.input !== undefined) captured.push(0);",
  "      else if (isPipeSlot(stdio[i])) captured.push(i);",
  "    }",
  "    if (captured.length === 0) return realSpawnSync.call(cp, file, cmdArgs, opts);",
  "",
  "    const encoding = opts.encoding === undefined || opts.encoding === null ? 'buffer' : opts.encoding;",
  "    let dir = tmpdir();",
  "    let madeDir = false;",
  "    try {",
  "      dir = mkdtempSync(join(tmpdir(), 'dsh-nopipe-'));",
  "      madeDir = true;",
  "    } catch { /* 临时区不可用时退回 tmpdir 本身，文件名仍然唯一 */ }",
  "",
  "    seq += 1;",
  "    const tag = String(process.pid) + '-' + String(seq);",
  "    const extra = Array.isArray(opts.stdio) && opts.stdio.length > 3 ? opts.stdio.slice(3) : [];",
  "    const nextStdio = stdio.slice();",
  "    const fds = [];",
  "    const files = [];",
  "    const bySlot = {};",
  "    try {",
  "      for (let k = 0; k < captured.length; k += 1) {",
  "        const slot = captured[k];",
  "        if (slot === 0 && opts.input === undefined) {",
  "          // 没有 input 就把 stdin 设成 ignore（与实测过的那条 ['ignore', fd, fd] 形状一致）",
  "          nextStdio[0] = 'ignore';",
  "          continue;",
  "        }",
  "        const kind = slot === 0 ? 'in' : (slot === 1 ? 'out' : 'err');",
  "        const path = join(dir, 'dsh-nopipe-' + tag + '-' + kind + '.tmp');",
  "        if (slot === 0) {",
  "          writeFileSync(path, opts.input);",
  "          const inFd = openSync(path, 'r');",
  "          fds.push(inFd);",
  "          nextStdio[0] = inFd;",
  "        } else {",
  "          const outFd = openSync(path, 'w');",
  "          fds.push(outFd);",
  "          nextStdio[slot] = outFd;",
  "        }",
  "        files.push(path);",
  "        bySlot[slot] = path;",
  "      }",
  "      const pass = Object.assign({}, opts);",
  "      pass.stdio = nextStdio.concat(extra);",
  "      delete pass.encoding;",
  "      if (opts.input !== undefined) delete pass.input;",
  "      const result = realSpawnSync.call(cp, file, cmdArgs, pass);",
  "      const readBack = (slot) => {",
  "        const path = bySlot[slot];",
  "        if (path === undefined) return undefined;",
  "        const buffer = readFileSync(path);",
  "        return encoding === 'buffer' ? buffer : buffer.toString(encoding);",
  "      };",
  "      const out = readBack(1);",
  "      const err = readBack(2);",
  "      const output = Array.isArray(result.output) ? result.output.slice() : [null, null, null];",
  "      while (output.length < 3) output.push(null);",
  "      if (out !== undefined) output[1] = out;",
  "      if (err !== undefined) output[2] = err;",
  "      const final = Object.assign({}, result, { output });",
  "      if (out !== undefined) final.stdout = out;",
  "      if (err !== undefined) final.stderr = err;",
  "      return final;",
  "    } finally {",
  "      for (let k = 0; k < fds.length; k += 1) {",
  "        try { closeSync(fds[k]); } catch { /* 忽略 */ }",
  "      }",
  "      for (let k = 0; k < files.length; k += 1) {",
  "        try { unlinkSync(files[k]); } catch { /* 忽略 */ }",
  "      }",
  "      if (madeDir) {",
  "        try { rmSync(dir, { recursive: true, force: true }); } catch { /* 忽略 */ }",
  "      }",
  "    }",
  "  };",
  "",
  "  // ★ 必须重新实现：Node 内部实现不经过被覆写的 cp.spawnSync 导出，只覆写导出盖不住 exec*Sync。",
  "  const execFileSyncWithFileStdio = (file, args, options) => {",
  "    const split = splitArgs(args, options);",
  "    if (split === null) throw new TypeError('args 必须是数组或 options 对象，收到 ' + typeof args);",
  "    const opts = split.options;",
  "    const cmdArgs = split.args;",
  "    const result = spawnSyncWithFileStdio(file, cmdArgs, opts);",
  "    if (result.error !== undefined && result.error !== null) throw result.error;",
  "    if (result.status !== 0) {",
  "      const shown = [String(file)].concat(cmdArgs.map(String)).join(' ');",
  "      const stderrText = result.stderr === undefined || result.stderr === null ? '' : String(result.stderr);",
  "      const failure = new Error('Command failed: ' + shown + LF + stderrText);",
  "      failure.status = result.status;",
  "      failure.signal = result.signal;",
  "      failure.stdout = result.stdout;",
  "      failure.stderr = result.stderr;",
  "      throw failure;",
  "    }",
  "    if (opts.stdio === undefined && result.stderr) process.stderr.write(result.stderr);",
  "    return result.stdout;",
  "  };",
  "",
  "  const execSyncWithFileStdio = (command, options) => {",
  "    const opts = options === undefined || options === null ? {} : Object.assign({}, options);",
  "    if (typeof opts.shell !== 'string' || opts.shell === '') {",
  "      opts.shell = process.env.ComSpec || process.env.comspec || 'cmd.exe';",
  "    }",
  "    return execFileSyncWithFileStdio(String(command), opts);",
  "  };",
  "",
  "  const unavailable = (api) => {",
  "    const error = new Error('[dsh-sandbox-mxc] 容器内不能用 ' + api",
  "      + ' 捕获子进程输出：容器令牌建不了命名管道，管道读取会永久挂住且 timeout 不生效。'",
  "      + '请改用同步 API（spawnSync / execFileSync / execSync，本 shim 已改成临时文件句柄），'",
  "      + '或把该工具放到容器外（宿主）运行。');",
  "    error.code = 'MXC_NAMED_PIPE_UNAVAILABLE';",
  "    throw error;",
  "  };",
  "  const asyncApis = ['spawn', 'exec', 'execFile', 'fork'];",
  "  for (let i = 0; i < asyncApis.length; i += 1) {",
  "    const apiName = asyncApis[i];",
  "    cp[apiName] = function () { unavailable(apiName); };",
  "  }",
  "",
  "  cp.spawnSync = spawnSyncWithFileStdio;",
  "  cp.execFileSync = execFileSyncWithFileStdio;",
  "  cp.execSync = execSyncWithFileStdio;",
  "}",
  "",
  "// 只为排查：写 stderr 而不是 stdout —— 免得污染容器内命令自己的标准输出（很多工具要解析它）。",
  "console.error('[dsh-sandbox-mxc] node 管道捕获 shim 已装载：异步 API 立即报错；同步 API 改用文件句柄');",
].join('\n');

/**
 * shim 的 --import 参数值（data:text/javascript, + 百分号编码源码）。
 * 只能内联：--import 只接受 file: / data: / node: 三种 scheme；且值里**不能有空格**
 * —— NODE_OPTIONS 以空格分词，含空格会把参数切碎。宿主已有的 NODE_OPTIONS 会保留在前面。
 * @returns {string} 形如 --import data:text/javascript,...
 */
export function nodeOptionsWithShim() {
  return '--import data:text/javascript,' + encodeURIComponent(NOPIPE_SHIM_SOURCE);
}

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
 * 过滤容器环境项（必须是 MXC 要求的 KEY=VALUE）。
 * 为什么丢掉而不报错：MXC 对 process.env 的**每一项**都要求 NAME=value，坏项会让
 * 整条命令 malformed ⇒ 与其让容器里每条命令都失败，不如丢掉并在这里说清楚。
 * @param {unknown} value 插件 config.sandboxEnv
 * @returns {string[]}
 */
function sandboxEnvEntries(value) {
  const raw = Array.isArray(value) ? value.filter((item) => typeof item === 'string' && item !== '') : [];
  const kept = [];
  for (const entry of raw) {
    if (entry.includes('=')) { kept.push(entry); continue; }
    console.warn('[dsh-sandbox-mxc] 忽略不含 = 的 sandboxEnv 项：' + entry + '（MXC 要求 KEY=VALUE）');
  }
  return kept;
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
    /** 额外注入容器的环境变量（KEY=VALUE），与 shim 注入的 NODE_OPTIONS 一起叠加到后端默认环境上。 */
    sandboxEnv: sandboxEnvEntries(cfg.sandboxEnv),
    /**
     * 是否给容器注入 Node 的“命名管道不可用”补偿 shim（默认 true，见 NOPIPE_SHIM_SOURCE）。
     * 关掉它 ⇒ 不碰 process.env / process.inheritDefaultEnv（除非显式配了 sandboxEnv）。
     */
    injectNodePipeShim: cfg.injectNodePipeShim === undefined ? true : cfg.injectNodePipeShim === true,
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
/**
 * ★ 只保留**这台机器上真实存在**的路径。
 *
 * 为什么必须过滤：DSH 的 `writableRoots()` 会带上 POSIX 风格的 `/tmp`（共享代码的写法），
 * 它在 Windows 上并不存在 ⇒ MXC 会拿它去申请写 DACL，失败后**整条策略被拒**、每条命令都跑不起来：
 *   error: BaseContainer is unavailable; DACL fallback requires write-DACL permission on '/tmp'
 * （实测：把 `/tmp` 从 readwritePaths 去掉，同一条命令立刻 status=0。）
 * BaseContainer 档下这个坑会被掩盖，但该档**每次开机都可能降级**到 AppContainer + DACL
 * （MXC 自己的警告如此），所以必须在这里挡住，不能指望档位。
 */
function existingPaths(paths) {
  return paths.filter((candidate) => typeof candidate === 'string' && candidate !== '' && existsSync(candidate));
}

export function buildPolicyConfig(policy, cfg, containerId = defaultContainerId(cfg.containerIdPrefix)) {
  const writable = existingPaths([...writableRoots(policy), ...cfg.extraWritablePaths].map(canonicalPath));
  // ★ 工作区必须始终**可读**：`read-only` 下 writableRoots 返回空，若不显式给只读根，
  //   容器连工作区里的文件都读不到（实测白名单之外连读都拒）⇒ 该档位会变得毫无用处。
  const readonly = [...cfg.readonlyPaths];
  if (policy.workspaceRoot !== undefined && policy.workspaceRoot !== '') {
    const workspaceCanonical = canonicalPath(policy.workspaceRoot);
    if (!writable.includes(workspaceCanonical)) readonly.push(policy.workspaceRoot);
  }
  // ★ 容器环境：wire 契约里 env / inheritDefaultEnv 是 **process** 的字段，不是顶层 ——
  //   generated/v1_0_0/wire.d.ts 的 Process 接口（env?: string[] / inheritDefaultEnv?: boolean），
  //   也是 SDK one-shot 绑定的实际读法（config.process?.env）。写到顶层会被 wire 直接忽略。
  const containerEnv = [...(cfg.sandboxEnv ?? [])];
  if (cfg.injectNodePipeShim) {
    const hostNodeOptions = (process.env.NODE_OPTIONS ?? '').trim();
    const shimOption = nodeOptionsWithShim();
    containerEnv.push('NODE_OPTIONS=' + (hostNodeOptions === '' ? shimOption : hostNodeOptions + ' ' + shimOption));
  }
  const processConfig = { commandLine: 'cmd /c exit 0', timeout: cfg.timeoutMs };
  if (containerEnv.length > 0) {
    processConfig.env = containerEnv;
    // 叠加到后端默认环境之上（不是替换）——否则容器会丢掉 PATH 之类的基础环境
    processConfig.inheritDefaultEnv = true;
  }
  const config = {
    version: MXC_CONTRACT_VERSION,
    containerId,
    lifecycle: { destroyOnExit: true, preservePolicy: false },
    // `-- <COMMAND>` 会覆盖 commandLine；这里给一个非空占位（wire 契约要求 process.commandLine 非空）
    process: processConfig,
    filesystem: {
      readwritePaths: [...new Set(writable)],
      readonlyPaths: [...new Set(existingPaths(readonly.map(canonicalPath)))],
      deniedPaths: [...new Set(existingPaths(cfg.deniedPaths.map(canonicalPath)))],
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
/**
 * ── 档位探测与便携适配 ──────────────────────────────────────────────────────
 * MXC 的隔离档（@microsoft/mxc-sdk 的 IsolationTier）：
 *   base-container     完整 BaseContainer（process security environment）⇒ **不需要** DACL 增补
 *   appcontainer-bfs   本二进制通常没编进去
 *   appcontainer-dacl  靠给策略里**每个路径写 DACL** 来授权
 * ⇒ 只有 dacl 系要求"本账号对策略里每个路径都有 WRITE_DAC"。在属主不是自己的卷上（便携盘、
 *   别人装好的盘）该前提不成立 ⇒ 整条策略被 MXC 拒绝、沙箱档下每条命令都跑不了。
 *   我们**不去改卷权限**（那是每机一次、可能上万文件的手术，不可移植），改成插件自己适配：
 *   探到 dacl 系 ⇒ 先用一条无害命令验证策略 ⇒ 把 MXC **明确报出来**授权不了的路径剔掉再试。
 *   结果按 wxc 路径缓存（进程内）⇒ 只在策略首次成型时付一次验证成本；强档下这段完全不执行。
 */
const tierCache = new Map();
const doomedPathsCache = new Map();

/** 从 `wxc-exec --probe` 的 stdout 解析档位（纯函数）。 */
export function parseTierFromProbe(stdout) {
  try {
    const parsed = JSON.parse(String(stdout).trim());
    return {
      tier: typeof parsed.tier === 'string' ? parsed.tier : 'unknown',
      needsDaclAugmentation: parsed.needsDaclAugmentation === true,
    };
  } catch { return { tier: 'unknown', needsDaclAugmentation: false }; }
}

/** 从 MXC 报错里抠出"授权不了的路径"（纯函数）。实测原文形如：
 *  `… requires write-DACL permission on 'X:\\toolchain\\app', which the current user lacks` */
export function pathsFromDaclError(stderr) {
  const found = [];
  for (const match of String(stderr).matchAll(/write-DAC(?:L)? permission on '([^']+)'/gu)) found.push(match[1]);
  return [...new Set(found)];
}

/** 把指定路径从策略三条列表里剔掉（纯函数）。 */
export function prunePolicyPaths(config, paths) {
  const drop = new Set(paths);
  const dropped = [];
  const filesystem = { ...config.filesystem };
  for (const key of ['readwritePaths', 'readonlyPaths', 'deniedPaths']) {
    const kept = [];
    for (const candidate of filesystem[key] ?? []) {
      if (drop.has(candidate)) dropped.push(key + ':' + candidate); else kept.push(candidate);
    }
    filesystem[key] = kept;
  }
  return { config: { ...config, filesystem }, dropped };
}

/**
 * 拼一条"逐个路径自检"的 cmd 命令（纯函数）：
 * 能列目录就打自己对勾，读不到就打 `MXCBAD <path>` —— 便于从 stdout 精确回收是哪条路径不行。
 * ★ 只用 `&` 串联、每条各自 `||`：cmd 里 `A || B & C || D` = `(A||B) & (C||D)`，正是我们要的。
 */
export function buildValidationCommand(paths) {
  const list = [...new Set(paths)].filter((p) => typeof p === 'string' && p !== '');
  if (list.length === 0) return 'exit 0';
  return list.map((p) => 'dir /b "' + p + '" >nul 2>&1 || echo MXCBAD ' + p).join(' & ');
}

/** 从自检输出里抠出"容器内读不到"的路径（纯函数）。 */
export function pathsFromValidationOutput(stdout) {
  const found = [];
  for (const line of String(stdout).split(/\r?\n/u)) {
    const match = line.trim().match(/^MXCBAD\s+(.+)$/u);
    if (match) found.push(match[1].trim());
  }
  return [...new Set(found)];
}

function probeTier(wxcExecPath) {
  let tier = tierCache.get(wxcExecPath);
  if (tier === undefined) {
    const run = spawnSync(wxcExecPath, ['--probe'], { encoding: 'utf8', timeout: 60000, windowsHide: true });
    tier = parseTierFromProbe(run.stdout ?? '');
    tierCache.set(wxcExecPath, tier);
  }
  return tier;
}

/**
 * dacl 系档位下把授权不了的路径从策略里剔掉，返回**最终的** config base64。
 * 强档、或一切顺利、或不是路径问题时，原样返回入参（绝不静默放行：只是让 MXC 去报错）。
 * @param {string} wxcExecPath
 * @param {string} configBase64
 * @param {(message: string) => void} [log]
 */
export function adaptConfigForTier(wxcExecPath, configBase64, log = console.warn, workspaceRoot = undefined) {
  const tier = probeTier(wxcExecPath);
  if (tier.tier === 'base-container') return configBase64;
  const doomed = doomedPathsCache.get(wxcExecPath) ?? new Set();
  doomedPathsCache.set(wxcExecPath, doomed);
  const cmdExe = (process.env.SystemRoot ?? 'C:\\Windows') + '\\System32\\cmd.exe';
  let encoded = configBase64;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    const { config: pruned, dropped } = prunePolicyPaths(parsed, doomed);
    if (dropped.length > 0) encoded = Buffer.from(JSON.stringify(pruned), 'utf8').toString('base64');
    // ★ 校验不止"容器起得来"：还逐个 `dir` 策略里的路径，把"起得来但里面读不到"也算出来
    // ★ 自检范围只限"可写根"，并且**排除工作区**：
    //   · 只读根不查 —— 实测 dir 会在"盘根未授权"的路径上失败，而 pwsh 自己反而能启动，
    //     于是会把它自己的安装目录（只读根）误剔、导致容器连 shell 都起不来；
    //     只读根真正不可用时，MXC 会用 write-DACL 报错说出来（那条路仍然有效）。
    //   · 工作区绝不能剔 —— 剔了命令就没地方写。
    const policyPaths = [...new Set(pruned.filesystem.readwritePaths ?? [])]
      .filter((candidate) => candidate !== workspaceRoot);
    const run = spawnSync(wxcExecPath, ['--config-base64', encoded, '--', cmdExe, '/c', buildValidationCommand(policyPaths)],
      { encoding: 'utf8', timeout: 60000, windowsHide: true });
    const unreachable = pathsFromValidationOutput(run.stdout ?? '');
    const unauthorized = pathsFromDaclError(run.stderr ?? '');
    if (run.status === 0 && unreachable.length === 0 && unauthorized.length === 0) return encoded;
    const bad = [...new Set([...unauthorized, ...unreachable])];
    if (bad.length === 0) return encoded;
    let added = false;
    for (const candidate of bad) {
      if (!doomed.has(candidate)) {
        doomed.add(candidate);
        added = true;
        log('[dsh-sandbox-mxc] 档位 ' + tier.tier + ' 下策略里的 ' + candidate + ' 无法使用'
          + '（MXC 报授权不足，或容器内读不到它）⇒ 已从沙箱策略里剔除。'
          + '要让它可用：把该目录放在自己拥有、容器也读得到的卷上；或让 MXC 使用 base-container 档（该档不需要 DACL 增补）。');
      }
    }
    if (!added) return encoded;
  }
  return encoded;
}

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
    const runnerArgv = buildRunnerArgv(argv, policy, this.config, wxcExecPath);
    // ★ 便携适配：dacl 系档位下剔掉本账号授权不了的路径（base-container 档是恒等变换）
    try {
      runnerArgv[2] = adaptConfigForTier(wxcExecPath, runnerArgv[2], console.warn, policy?.workspaceRoot);
    } catch { /* 适配本身失败不改主流程：让 MXC 照原策略报错，比静默放行安全 */ }
    return {
      argv: runnerArgv,
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
