# dsh-sandbox-mxc

A DeepSeek Harness **sandbox provider** backed by
[MXC](https://www.npmjs.com/package/@microsoft/mxc-sdk) (Microsoft eXecution Containers).

It implements the harness's process-confinement seam (`ctx.sandbox`, a
`SandboxProvider` from `@deepseek-ai/dsh-sandbox`) by wrapping the exact argv the caller is about to
spawn:

```
wxc-exec.exe --config-base64 <policy-json> -- <original argv...>
```

- **No `@microsoft/mxc-sdk` import.** The plugin never loads the SDK's native bindings — it only needs
  the `wxc-exec` executable, located with `require.resolve`. So the SDK's
  *“native stdio on Windows requires Node.js 24.21.0 or newer within Node.js 24, or Node.js 26.8.0
  or newer”* restriction **does not apply**. It runs on the Node inside the harness (verified on
  `v24.20.0`).
- **One runtime dependency:** `@microsoft/mxc-sdk` (declared in `dependencies`; used *only* to locate
  `wxc-exec.exe`). Config validation is hand-written; no schema library.
- **No kernel patch.** It is a sibling provider to `@deepseek-ai/dsh-sandbox-local`, selected through
  the harness's normal bundle-patch layer.
- **Policy semantics are not re-implemented here.** Read/write roots come from
  `writableRoots(policy)` / `canonicalPath(path)` exported by `@deepseek-ai/dsh-sandbox`, so the
  meaning of `read-only` / `workspace-write` stays in one place.

## Requirements

- **Windows.** This provider drives MXC's Windows backends (`wxc-exec.exe`, ProcessContainer / AppContainer).
- **DeepSeek Harness** that mounts the `sandbox` service (`@deepseek-ai/dsh-sandbox` — declared in `peerDependencies`; never bundled).
- **Node.js `>=22`** — the harness's own Node is fine.
- **`wxc-exec.exe`** — resolved from the installed `@microsoft/mxc-sdk` (a normal dependency), else `config.wxcExecPath`, else `$DSH_MXC_WXC`.
- **An *unpackaged* PowerShell**, when the profile's pwsh tool points at a Store/MSIX build: MXC containers **cannot launch packaged (MSIX) apps**
  (`The target executable '…\WindowsApps\…\pwsh.exe' appears to be a packaged (MSIX) app`). Point the executor's `pwshPath` at an unpackaged
  build — e.g. the official ZIP extracted to a stable directory of your choosing.
- **That shell's own install directory must be readable inside the container** — list it in `config.readonlyPaths`. An unpackaged PowerShell
  resolves its own path at startup and otherwise fails with `Failed to resolve full path of the current executable`.
- **Paths that do not exist on this machine are dropped automatically.** Handing one to MXC makes it reject the *whole* policy
  (`DACL fallback requires write-DACL permission on '/tmp'` — `/tmp` is what the shared harness code contributes on Windows), so the
  provider filters every path list through an existence check before building the policy.
- **On MXC's `appcontainer-dacl` tier**, the account must be able to write a DACL for every path in the policy. When it cannot — a volume
  owned by another SID, or a path the container turns out not to be able to read — the provider **drops that path and prints why**, instead
  of failing the command, and caches the verdict. It never asks for per-machine ACL surgery. The strong `base-container` tier needs no
  DACL work at all.

## Verified environment

Measured on the development machine; it is a record, not a claim about yours.

| Item | Value |
|---|---|
| OS | Windows (x64) |
| Harness | DSH `0.2.0-rc.2` |
| Node.js | `v24.20.0` (the harness's own) |
| Shell | PowerShell `7.7.0-preview.5`, **unpackaged** (ZIP-extracted) |
| MXC | `@microsoft/mxc-sdk` `1.0.0`; `wxc-exec --probe` reported the **BaseContainer** tier on a Windows 11 host and the **AppContainer + DACL** tier on a Windows 10 host |

Measured behaviour (the full matrix is under `## Security posture`): workspace writes allowed; writes **and reads** outside the policy denied;
outbound network blocked by default; clipboard isolated from the host. Two tier-dependent facts are worth knowing before trusting a machine:

- **`base-container` needs Windows 11; Windows 10 can only use the DACL tier.** Same binary, two hosts:
  on **Windows 11** (build ≥ 26100) `wxc-exec --probe` reports `tier=base-container / needsDaclAugmentation=false /
  baseContainerApiPresent=true`; on **Windows 10** it reports `tier=appcontainer-dacl /
  needsDaclAugmentation=true / baseContainerApiPresent=false` — the process-security-environment API the strong tier needs is
  simply not there, so on Windows 10 every path in the policy must be DACL-augmentable (see `## Requirements`, where the provider
  handles that by dropping and reporting). `wxc-host-prep.exe` (elevated) clears the system-drive and NUL-device warnings but
  cannot create the missing API.

## Install

Two things are independent: **(a)** installing this plugin, and **(b)** making a `wxc-exec`
executable reachable.

### (a) Install the plugin into a profile

Local checkout (development, and the usual way for a git-only plugin):

```powershell
# 1. put the repo somewhere stable, then link it into the profile
#    <profile>/package.json :  "dsh-sandbox-mxc": "link:<absolute-path-to-this-repo>"
# 2. add it to the profile's bundle list:
#    "dsh": { "profile": { "bundles": [ "...", "dsh-sandbox-mxc" ] } }
# 3. create the node_modules junction:
#    <profile>/node_modules/dsh-sandbox-mxc  ->  <absolute-path-to-this-repo>
```

From a registry (if you publish it):

```powershell
dsh plugin --profile <profile> add dsh-sandbox-mxc
```

Either way the plugin's own `cordis.patch.yml` is applied, which

1. disables the default provider row (`- id: sandbox` → `@deepseek-ai/dsh-sandbox-local`), and
2. inserts this plugin — it provides the **same service name** `sandbox`, so every consumer
   (`pwsh`, `bash`, and filesystem tool families) is unchanged.

> The Cordis patch dialect treats a truthy `name` as an **assertion** on an existing row, not a
> rename — which is why the patch disables the old row and inserts a new one instead of editing
> `name` in place.
>
> **Restart the profile** after changing the patch: the provider lives on the host plane.

### (b) Make `wxc-exec` reachable

In order of precedence:

1. plugin `config.wxcExecPath` (absolute path to `wxc-exec.exe`);
2. environment variable `DSH_MXC_WXC`;
3. derivation from an installed `@microsoft/mxc-sdk`: `<package>/bin/x64/wxc-exec.exe`.

If none resolves, `confine()` **fails closed** — it throws `SandboxUnavailableError` (code
`SANDBOX_UNAVAILABLE`) rather than letting a command run unconfined. Installing
`@microsoft/mxc-sdk` is a normal runtime dependency (declared in `dependencies`, installed from npm);
it is never imported — it is used only to locate `wxc-exec.exe`.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `wxcExecPath` | `''` | Absolute path to `wxc-exec.exe`. Empty ⇒ try `DSH_MXC_WXC`, then derive from `@microsoft/mxc-sdk`. |
| `readonlyPaths` | `[]` | Extra roots the container may **read** (beyond the workspace). |
| `extraWritablePaths` | `[]` | Extra roots the container may **write** (beyond `writableRoots(policy)`). |
| `deniedPaths` | `[]` | Roots the container may never touch (MXC `filesystem.deniedPaths`). |
| `network` | omitted | Omitted ⇒ MXC default, which is **block** (measured `default_policy=block`). |
| `timeoutMs` | `0` | Per-execution timeout in milliseconds; `0` = none. |
| `containerIdPrefix` | `'dsh-mxc'` | Prefix for the diagnostic container name. |
| `sandboxEnv` | `[]` | Extra `KEY=VALUE` entries for the container's `process.env`, layered on the backend default (`inheritDefaultEnv: true`). Entries without `=` are dropped with a warning (MXC rejects such a command outright). |
| `injectNodePipeShim` | `true` | Inject `NODE_OPTIONS=--import data:text/javascript,…` so Node **inside the container** captures child-process output through file handles instead of named pipes, and fails fast on the async APIs. `false` leaves `process.env` / `process.inheritDefaultEnv` untouched. See *Container environment* below. |

```yaml
- insert:
    - id: sandbox-mxc
      name: dsh-sandbox-mxc
      config:
        wxcExecPath: !!js process.env.DSH_MXC_WXC ?? ''
        readonlyPaths: []
```

### Container environment (the Node named-pipe shim)

Inside an MXC container the process token cannot create **named pipes** — which is exactly how libuv
implements `stdio: 'pipe'`. Measured in one container on this machine:

| Call inside the container | Result |
|---|---|
| `spawnSync(cmd.exe, ['/c','echo','hi'], { encoding: 'utf8', timeout: 300 })` | **never returns**; `timeout` / `killSignal` do not fire |
| `spawnSync(…, { stdio: ['ignore', fd, fd] })` (file handles) | returns in **6–10 ms** |
| `stdio: 'inherit'` / `'ignore'` | returns in 6–10 ms |
| `.NET NamedPipeServerStream` / `net.listen` | `Access to the path is denied` / `EADDRINUSE` |

So with `injectNodePipeShim: true` (the default) the provider adds one `NODE_OPTIONS` entry — an inline
`data:text/javascript,…` preload, so **no file is written** — which, inside the container, changes
`child_process` for every Node process the command starts:

- **`spawnSync` / `execFileSync` / `execSync`** — stdout/stderr are captured through **temporary file
  descriptors** and read back; a slot stays a pipe only if the caller asked for something else.
  `execFileSync` / `execSync` are re-implemented on purpose: Node’s own implementations do not go
  through the overridden `spawnSync` export, so overriding the export alone would not cover them. The
  `exec*Sync` error shape (`status` / `stdout` / `stderr`, message starting with `Command failed: `) and
  Node's default `encoding: 'buffer'` are preserved; `maxBuffer` no longer applies (output goes to a file).
- **`spawn` / `exec` / `execFile` / `fork`** — **throw immediately** with
  `code: 'MXC_NAMED_PIPE_UNAVAILABLE'` and a message naming the API, instead of hanging forever.

Notes: the shim also governs any Node process the container’s command starts (`NODE_OPTIONS` is
inherited — that is the point), and a command that genuinely needs asynchronous child processes has to
run **outside** the container. Set `injectNodePipeShim: false` to leave the container environment exactly
as it was before this feature.

The shim travels in the **command line** (environment → config JSON → `--config-base64`), and Windows
caps a command line at ≈32767 characters — so the inlined source is kept comment-lean and the patch
script asserts the encoded size (currently ≈14566 characters for the `NODE_OPTIONS` entry).
### Mode mapping

| Harness mode | MXC `filesystem` |
|---|---|
| `read-only` | `readwritePaths: []`, and the workspace root is added to `readonlyPaths` (without that, the container could not even *read* the workspace) |
| `workspace-write` | `readwritePaths: writableRoots(policy)` (workspace root + platform temp areas) |
| `danger-full-access` | `confine()` is not called by the harness |

`ui` is always pinned to `{ disable: false, clipboard: 'none', injection: false }` and
`processContainer.ui` to `{ isolation: 'container', desktopSystemControl: false, systemSettings:
'none', ime: false }`.

## Security posture (measured, not assumed)

| Property | Measured result |
|---|---|
| Backend | `BaseContainer` (confirmed from `--debug` native logs; **no `--experimental` needed**) |
| ACL augmentation | `--probe` reports `needsDaclAugmentation: false` — it does **not** need the write-authorization step that the bundled ACL provider requires |
| Filesystem | Outside the allow-list **even reads are denied**; writes outside `readwritePaths` are denied; a read-only root cannot be written |
| Network | Blocked by default (`default_policy=block`) |
| Clipboard | `clipboard:'none'` **is enforced**: a host clipboard marker was invisible to the container, and a container marker never reached the host clipboard. *Note: enforcement is a silent no-op — it does not raise an error.* |
| `ui.disable` | Must be `false`, otherwise the container blocks Win32k and `node.exe` / `pwsh` fail with `0xC0000142 STATUS_DLL_INIT_FAILED` |
| Container environment | The container does **not** inherit the host `PATH` / environment — configure `environment` when your commands need a toolchain |
| Screen / desktop | **Undetermined.** Window enumeration returned 0 inside the container (14 on the host), but “separate desktop” and “synthetic user without enumeration rights” both explain that, so no conclusion is drawn |

Cost of `ui.disable: false`: Win32k becomes reachable from the container, i.e. the kernel attack
surface is wider than a fully UI-less container — the unavoidable price of running a native Windows
`node.exe`/`pwsh`. Clipboard and input injection stay closed, and the harness's bundled ACL provider
does not isolate that surface either, so this is not a regression there.

## Tests

```powershell
node --test "tests/**/*.test.mjs"
```

Covers: policy→config mapping (including the empty writable set under `read-only`), the argv shape
and the `--` separator, base64 round-trip, the pinned security defaults, and fail-closed resolution.

## License

MIT — see [LICENSE](LICENSE).
