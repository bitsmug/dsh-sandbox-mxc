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
import { canonicalPath } from '@deepseek-ai/dsh-sandbox';
import {
  buildPolicyConfig,
  buildRunnerArgv,
  MXC_CONTRACT_VERSION,
  normalizeConfig,
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
  const cfg = normalizeConfig({ extraWritablePaths: ['C:/fixture-extra'] });
  const config = buildPolicyConfig(POLICY_WRITE, cfg, 'unit-test');

  assert.equal(config.version, MXC_CONTRACT_VERSION);
  assert.equal(config.containerId, 'unit-test');
  // 工作区根在可写集合里（canonical，与 writableRoots 的拼写一致）
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath(POLICY_WRITE.workspaceRoot)),
    `工作区必须在可写集合：${JSON.stringify(config.filesystem.readwritePaths)}`);
  // 平台临时区也应在（mode 的语义由 dsh-sandbox 决定，不在这里重写）
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath(tmpdir())),
    '临时区必须可写（否则 mkstemp 家族工具跑不起来）');
  // 额外可写
  assert.ok(config.filesystem.readwritePaths.includes(canonicalPath('C:/fixture-extra')));

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
