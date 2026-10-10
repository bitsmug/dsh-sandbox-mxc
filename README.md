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

```yaml
- insert:
    - id: sandbox-mxc
      name: dsh-sandbox-mxc
      config:
        wxcExecPath: !!js process.env.DSH_MXC_WXC ?? ''
        readonlyPaths: []
```

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
