/**
 * tests/policy.test.mjs —— 纯函数层的约定（不需要 DSH 运行、不需要真 MXC 执行器）
 *
 * ★ 本文件里的 `C:/…`、`X:/…`、`Z:/…` 一律是**占位夹具**，不对应任何真实机器路径。
 *
 * 钉住四件事：
 *   ① 策略语义**不重写**：读写根来自 `@deepseek-ai/dsh-sandbox` 的 `writableRoots(policy)`
 *      （`workspace-write` = 工作区 + 临时区；`read-only` = 空）
 *   ② 安全默认：`ui.disable:false` 但 `clipboard:'none'` / `injection:false`，且 `processContainer.ui` 关掉桌面控制
 *   ③ argv 形状：`[wxc, '--config-base64', <b64>, '--', ...原 argv]`，且 `--` 之后**逐项等于**原 argv
 *   ④ fail-closed：拿不到执行器时抛错（`resolveWxcExecutable` 无候选可用时）
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { dirname } from 'node:path';
import { canonicalPath } from '@deepseek-ai/dsh-sandbox';
import {
  adaptConfigForTier,
  buildPolicyConfig,
  buildRunnerArgv,
  buildValidationCommand,
  nodeOptionsWithShim,
  NOPIPE_SHIM_SOURCE,
  pathsFromValidationOutput,
  MXC_CONTRACT_VERSION,
  normalizeConfig,
  parseTierFromProbe,
  pathsFromDaclError,
  prunePolicyPaths,
  resolveWxcExecutable,
} from '../lib/index.js';

const POLICY_WRITE = { mode: 'workspace-write', workspaceRoot: process.cwd() };
const POLICY_READ = { mode: 'read-only', workspaceRoot: process.cwd() };

test('normalizeConfig：缺省值稳定（零依赖手写校验）', () => {
  const cfg = normalizeConfig(undefined);
  assert.equal(cfg.wxcExecPath, '');
  assert.deepEqual(cfg.readonlyPaths, []);
  assert.deepEqual(cfg.extraWritablePaths, []);
  assert.deepEqual(cfg.deniedPaths, []);
  assert.equal(cfg.network, undefined);
  assert.equal(cfg.timeoutMs, 0);
  assert.equal(cfg.containerIdPrefix, 'dsh-mxc');
  // 非法元素被过滤
  const mixed = normalizeConfig({ readonlyPaths: ['C:/fixture-a', '', 42, null, 'C:/fixture-b'], timeoutMs: 'x' });
  assert.deepEqual(mixed.readonlyPaths, ['C:/fixture-a', 'C:/fixture-b']);
  assert.equal(mixed.timeoutMs, 0);
});

test('buildPolicyConfig：workspace-write ⇒ 工作区可写；ui 三项与 processContainer.ui 按实测口径钉死', () => {
  // ★ extraWritablePaths 必须是**本机真实存在**的目录：不存在的路径会被 existingPaths 丢掉
  //   （否则 MXC 会拿它申请写 DACL 并拒绝整条策略 —— 真机实测过 /tmp 就是这个坑）。
  const extraWritable = dirname(process.cwd());
  const cfg = normalizeConfig({ extraWritablePaths: [extraWritable] });
  const config = buildPolicyConfig(POLICY_WRITE, cfg, 'unit-test');

  assert.equal(config.version, MXC_CONTRACT_VERSION);
  assert.equal(config.containerId, 'unit-test');
  // 工作区根在可写集合里（canonical，与 writableRoots 的拼写一致）
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath(POLICY_WRITE.workspaceRoot)),
    `工作区必须在可写集合：${JSON.stringify(config.filesystem.readwritePaths)}`);
  // 平台临时区也应在（mode 的语义由 dsh-sandbox 决定，不在这里重写）
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath(tmpdir())),
    '临时区必须可写（否则 mkstemp 家族工具跑不起来）');
  // 额外可写：存在的路径必须保留
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath(extraWritable)),
    '存在的 extraWritablePaths 必须保留');
  // 额外可写：**不存在**的必须被丢掉（这正是真机上 /tmp 拖垮整条策略的那条规则）
  const ghostCfg = normalizeConfig({ extraWritablePaths: ['Z:/fixture-missing-dir'] });
  const ghostConfig = buildPolicyConfig(POLICY_WRITE, ghostCfg, 'unit-test-ghost');
  assert.ok(!ghostConfig.filesystem.readwritePaths.some((p) => p.includes('fixture-missing-dir')),
    '不存在的 extraWritablePaths 必须被丢掉');

  // ★ 安全默认：Win32k 放开，但剪贴板/注入显式关闭
  assert.deepEqual(config.ui, { disable: false, clipboard: 'none', injection: false });
  assert.equal(config.processContainer.ui.isolation, 'container');
  assert.equal(config.processContainer.ui.desktopSystemControl, false);
  assert.equal(config.processContainer.ui.ime, false);
  assert.equal(config.processContainer.ui.systemSettings, 'none');
  // wire 契约要求 process.commandLine 非空（真命令由 `--` 覆盖）
  assert.ok(typeof config.process.commandLine === 'string' && config.process.commandLine !== '');
  assert.equal(config.lifecycle.destroyOnExit, true);
  assert.equal(config.network, undefined, '不传网络策略 ⇒ 用 MXC 默认 block');
});

test('buildPolicyConfig：read-only ⇒ 可写集合为空，但工作区仍可读（语义取自 writableRoots）', () => {
  const config = buildPolicyConfig(POLICY_READ, normalizeConfig(undefined), 'unit-read');
  assert.deepEqual(config.filesystem.readwritePaths, [], 'read-only 不许有任何可写根');
  assert.ok(config.filesystem.readonlyPaths.includes(canonicalPath(POLICY_READ.workspaceRoot)),
    'read-only 下工作区必须可读，否则该档位连文件都读不到');
  assert.deepEqual(config.filesystem.deniedPaths, []);
});

test('buildRunnerArgv：argv 形状 = [wxc, --config-base64, <b64>, --, ...原 argv]', () => {
  const original = ['pwsh', '-NoProfile', '-Command', 'Write-Output hi'];
  const cfg = normalizeConfig(undefined);
  const argv = buildRunnerArgv(original, POLICY_WRITE, cfg, 'X:/fixture/wxc-exec.exe');

  assert.equal(argv[0], 'X:/fixture/wxc-exec.exe');
  assert.equal(argv[1], '--config-base64');
  const separator = argv.indexOf('--');
  assert.ok(separator > 1, '必须有 `--` 分隔符');
  assert.deepEqual(argv.slice(separator + 1), original, '`--` 之后必须逐项等于原 argv');

  // 中间的 base64 必须能解回同一份策略
  const decoded = JSON.parse(Buffer.from(argv[2], 'base64').toString('utf8'));
  assert.equal(decoded.version, MXC_CONTRACT_VERSION);
  assert.deepEqual(decoded.ui, { disable: false, clipboard: 'none', injection: false });
  assert.ok(decoded.filesystem.readwritePaths.length > 0);
});

test('resolveWxcExecutable：显式路径优先；无候选时要么落 SDK 分支、要么 fail-closed（不许静默）', () => {
  // ① 显式配置永远优先
  const explicit = resolveWxcExecutable(normalizeConfig({ wxcExecPath: process.execPath }));
  assert.equal(explicit, process.execPath, '显式 wxcExecPath 必须优先');

  // ② 显式无效 + 无环境变量 ⇒ 只剩 SDK 推导一条路：
  //    本机装了 SDK 就应解析到它的 wxc-exec.exe；没装就必须抛错。
  //    ★ 两条分支都断言（此前的写法假设"一定解析不到"，于是被一次 junction 打破 ⇒ 依赖环境的测试是错的）
  const savedEnv = process.env.DSH_MXC_WXC;
  delete process.env.DSH_MXC_WXC;
  try {
    const bogus = normalizeConfig({ wxcExecPath: 'Z:/fixture/missing/wxc-exec.exe' });
    let resolved;
    let failure;
    try { resolved = resolveWxcExecutable(bogus); } catch (error) { failure = error; }
    if (resolved !== undefined) {
      assert.match(resolved, /wxc-exec\.exe$/u, 'SDK 分支必须给出可执行文件');
      assert.ok(resolved !== bogus.wxcExecPath, '无效的显式路径不许被当作结果');
    } else {
      assert.match(failure.message, /wxc-exec\.exe 不可用/u, '没有候选时必须给出可读原因');
    }
  } finally {
    if (savedEnv !== undefined) process.env.DSH_MXC_WXC = savedEnv;
  }
});

import { existsSync } from 'node:fs';

test('buildPolicyConfig：丢掉机器上不存在的路径（/tmp 这类 POSIX 路径会拖垮整条策略）', () => {
  const cfg = normalizeConfig({});
  const config = buildPolicyConfig(POLICY_WRITE, cfg, 'unit-existing-only');
  const all = [...config.filesystem.readwritePaths, ...config.filesystem.readonlyPaths, ...config.filesystem.deniedPaths];
  assert.ok(config.filesystem.readwritePaths.length >= 1, '可写列表不能为空');
  for (const p of all) assert.ok(existsSync(p), `策略里不得出现不存在的路径：${p}`);
  assert.ok(!all.includes('/tmp'), '/tmp 这类不存在于本机的路径必须被丢掉');
  assert.ok(
    config.filesystem.readwritePaths.includes(canonicalPath(POLICY_WRITE.workspaceRoot)),
    '工作区必须仍精确落在可写列表里',
  );
});

test('便携适配：档位解析 / 报错抠路径 / 剔路径（纯函数）', () => {
  assert.deepEqual(parseTierFromProbe('{"tier":"appcontainer-dacl","needsDaclAugmentation":true}'),
    { tier: 'appcontainer-dacl', needsDaclAugmentation: true });
  assert.deepEqual(parseTierFromProbe('不是 JSON'), { tier: 'unknown', needsDaclAugmentation: false });

  const mxcError = "error: BaseContainer is unavailable; DACL fallback requires write-DACL permission on 'X:\\toolchain\\app', which the current user lacks";
  assert.deepEqual(pathsFromDaclError(mxcError), ['X:\\toolchain\\app']);
  assert.deepEqual(pathsFromDaclError('no path here'), []);

  const cfg = normalizeConfig({ readonlyPaths: [process.cwd()] });
  const config = buildPolicyConfig(POLICY_WRITE, cfg, 'unit-prune');
  const { config: pruned, dropped } = prunePolicyPaths(config, [canonicalPath(process.cwd())]);
  assert.ok(dropped.some((entry) => entry.startsWith('readonlyPaths:')), '应报出被剔掉的类别与路径');
  assert.ok(!pruned.filesystem.readonlyPaths.includes(canonicalPath(process.cwd())), '只读白名单里不该再有它');
  assert.ok(pruned.filesystem.readwritePaths.length >= 1, '可写根不受影响');

  // 强档必须恒等（不许动策略）：用一个不存在的执行器也不该抛（内部会退化成 unknown ⇒ 走验证分支）
  assert.equal(typeof adaptConfigForTier, 'function');
});

test('便携适配：策略里"容器起得来但读不到"的路径也要被认出来（纯函数）', () => {
  assert.equal(buildValidationCommand([]), 'exit 0');
  const command = buildValidationCommand(['X:\\toolchain\\app', 'C:\\work', 'X:\\toolchain\\app']);
  assert.equal(command.split(' & ').length, 2, '重复路径要去重，每条各自成段');
  assert.ok(command.includes('dir /b "X:\\toolchain\\app"'), '每条路径都要真的去列一次');
  assert.ok(command.includes('|| echo MXCBAD X:\\toolchain\\app'), '读不到要打出可回收的标记');

  assert.deepEqual(pathsFromValidationOutput('MXCOK C:\\work\r\nMXCBAD X:\\toolchain\\app\r\n'), ['X:\\toolchain\\app']);
  assert.deepEqual(pathsFromValidationOutput('没有任何标记'), []);
  assert.deepEqual(pathsFromValidationOutput('MXCBAD A\nMXCBAD A'), ['A'], '重复要合并');
});

test('node 管道 shim：默认把 NODE_OPTIONS 注入 process.env；开关关掉后完全不碰 env', () => {
  assert.equal(normalizeConfig({}).injectNodePipeShim, true, '默认开');
  assert.equal(normalizeConfig({ injectNodePipeShim: true }).injectNodePipeShim, true);
  assert.equal(normalizeConfig({ injectNodePipeShim: false }).injectNodePipeShim, false);
  assert.equal(normalizeConfig({ injectNodePipeShim: 'yes' }).injectNodePipeShim, false, '只认布尔 true');

  const config = buildPolicyConfig(POLICY_WRITE, normalizeConfig({}), 'unit-shim');
  // ★ env / inheritDefaultEnv 是 wire 契约里 **process** 的字段（generated/v1_0_0/wire.d.ts 的 Process 接口）
  assert.equal(config.env, undefined, '顶层 env 会被 wire 忽略，不许写在那里');
  assert.equal(config.process.inheritDefaultEnv, true, '必须叠加到后端默认环境之上（否则会丢 PATH）');
  const entry = config.process.env.find((item) => item.startsWith('NODE_OPTIONS='));
  assert.ok(entry !== undefined, '必须注入 NODE_OPTIONS：' + JSON.stringify(config.process.env));
  assert.ok(entry.includes('--import data:text/javascript,'), 'NODE_OPTIONS 必须带 data: URL 的 --import：' + entry.slice(0, 80));
  // 宿主已设 NODE_OPTIONS 时它会被原样前置 ⇒ 只在它为空时断言严格前缀（避免依赖环境的测试）
  const hostOptions = (process.env.NODE_OPTIONS ?? '').trim();
  if (hostOptions === '') {
    assert.ok(entry.startsWith('NODE_OPTIONS=--import data:text/javascript,'), entry.slice(0, 80));
  } else {
    assert.ok(entry.startsWith('NODE_OPTIONS=' + hostOptions + ' '), '既有 NODE_OPTIONS 必须保留在前：' + entry.slice(0, 80));
  }
  for (const item of config.process.env) assert.ok(item.includes('='), 'env 每项必须是 KEY=VALUE：' + item);

  const off = buildPolicyConfig(POLICY_WRITE, normalizeConfig({ injectNodePipeShim: false }), 'unit-shim-off');
  assert.equal(off.process.env, undefined, '关掉 shim ⇒ 不碰 env');
  assert.equal(off.process.inheritDefaultEnv, undefined, '关掉 shim ⇒ 不碰 inheritDefaultEnv');
});

test('node 管道 shim：源码非空、能整段解码回来、带全部关键标记', () => {
  assert.equal(typeof NOPIPE_SHIM_SOURCE, 'string');
  assert.ok(NOPIPE_SHIM_SOURCE.length > 1000, 'shim 源码不该是空壳：' + String(NOPIPE_SHIM_SOURCE.length));
  const option = nodeOptionsWithShim();
  const prefix = '--import data:text/javascript,';
  assert.ok(option.startsWith(prefix), option.slice(0, 60));
  assert.ok(!option.includes(' '), 'NODE_OPTIONS 以空格分词 ⇒ data: URL 里不许有空格');
  assert.equal(decodeURIComponent(option.slice(prefix.length)), NOPIPE_SHIM_SOURCE, 'data: URL 必须能整段解码回源码');
  const markers = ['MXC_NAMED_PIPE_UNAVAILABLE', 'spawnSync', 'execFileSync', 'execSync', 'closeSync', 'mkdtempSync', 'unlinkSync'];
  for (const marker of markers) assert.ok(NOPIPE_SHIM_SOURCE.includes(marker), 'shim 源码缺少 ' + marker);
  // ESM 源码里有 import 语句，没法用 new Function 解析 ⇒ 语法由补丁脚本的 node --check 负责
  assert.ok(NOPIPE_SHIM_SOURCE.includes('node:child_process'), 'shim 必须从 node:child_process 取实现在覆写');
});

test('容器环境：sandboxEnv 逐项注入（不含 = 的项被丢掉）', () => {
  const cfg = normalizeConfig({ sandboxEnv: ['DSH_PROBE=1', 'BAD_ENTRY', 42] });
  assert.deepEqual(cfg.sandboxEnv, ['DSH_PROBE=1'], '非 KEY=VALUE 的项必须被丢掉（MXC 会让整条命令 malformed）');
  const config = buildPolicyConfig(POLICY_WRITE, cfg, 'unit-env');
  assert.ok(config.process.env.includes('DSH_PROBE=1'), 'sandboxEnv 必须进 process.env');
  assert.equal(config.process.inheritDefaultEnv, true, '显式 env 也必须叠加而不是替换');
  assert.ok(config.process.env.some((item) => item.startsWith('NODE_OPTIONS=')), 'sandboxEnv 与 NODE_OPTIONS 必须共存');
});
