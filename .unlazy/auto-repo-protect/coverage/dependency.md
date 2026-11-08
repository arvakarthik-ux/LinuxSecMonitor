# Dependency Installation Coverage Analysis

## Overview

Dependency installation is the **highest-risk execution vector** because:
1. Fetches and executes code from untrusted sources
2. Runs with user's full privileges
3. Often executes during routine development workflow
4. Can execute arbitrary code via lifecycle hooks

---

## npm / Node.js

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `npm install` | Install dependencies | Yes (lifecycle scripts) |
| `npm ci` | Clean install | Yes (lifecycle scripts) |
| `npm install <pkg>` | Add dependency | Yes (lifecycle scripts) |
| `npx <cmd>` | Execute package binary | Yes (downloads + runs) |
| `npm run <script>` | Run package script | Yes (arbitrary shell) |
| `npm pack` | Create tarball | No (but reads scripts) |

### Lifecycle Scripts (Execution Points)
| Script | When Runs | Risk |
|---|---|---|
| `preinstall` | Before install | High - runs before any files written |
| `install` | After install | High - runs after files written |
| `postinstall` | After install | High - common for native builds |
| `prepare` | Before pack, after install | High - runs in git repos too |
| `prepublishOnly` | Before publish | Medium |
| `prepack` / `postpack` | During pack | Medium |

### Dependency Sources
| Source | Example | Inspection Possible |
|---|---|---|
| Registry | `npm install lodash` | Yes (tarball from registry) |
| Git | `npm install git+https://...` | Yes (clone + scan) |
| GitHub | `npm install user/repo` | Yes (clone + scan) |
| Local | `npm install ../pkg` | Yes (local scan) |
| Tarball | `npm install ./pkg.tgz` | Yes (extract + scan) |

### Inspection Strategy
1. **Pre-install scan**: Download/extract to temp, scan, then install
2. **package.json analysis**: Static scan of all dependencies' manifests
3. **Lockfile validation**: Ensure `package-lock.json` matches approved versions
4. **Override approval**: User approves each new dependency with lifecycle scripts

### Bypass Analysis
| Bypass | Method | Mitigation |
|---|---|---|
| `/usr/bin/npm` | Direct binary | Document |
| `npm install --ignore-scripts` | Skip lifecycle | User must know flag |
| `npm_config_ignore_scripts=true` | Env var | Document |
| `npx` | Downloads + runs | Wrapper npx |
| Workspaces | Multiple package.json | Scan all workspaces |
| `--legacy-peer-deps` | Bypass peer checks | Still runs scripts |

---

## pip / Python

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `pip install` | Install package | Yes (setup.py, build backend) |
| `pip install -r req.txt` | Install from requirements | Yes |
| `pip install -e .` | Editable install | Yes (setup.py) |
| `pip install git+https://...` | Git dependency | Yes (clone + setup.py) |
| `pip wheel` | Build wheel | Yes (build backend) |

### Execution Points
| Point | Mechanism | Risk |
|---|---|---|
| `setup.py` | Arbitrary Python | Very High |
| `pyproject.toml` build-backend | Arbitrary Python | Very High |
| `setup.cfg` | Configuration | Low |
| `pip install --no-build-isolation` | Uses env Python | High |

### Dependency Sources
| Source | Example | Inspection |
|---|---|---|
| PyPI | `pip install requests` | Wheel/sdist scan |
| Git | `pip install git+https://...` | Clone + scan |
| Local | `pip install ./pkg` | Local scan |
| URL | `pip install https://.../pkg.whl` | Download + scan |

### Inspection Strategy
1. **Download to temp**: `pip download --no-deps` or `pip wheel`
2. **Scan extracted source**: setup.py, pyproject.toml, source files
3. **Check build backend**: setuptools, flit, poetry, maturin, etc.
4. **Approve before install**: Show findings, require confirmation

### Bypass Analysis
| Bypass | Method | Mitigation |
|---|---|---|
| `/usr/bin/pip` | Direct binary | Document |
| `--no-build-isolation` | Uses current env | Still scans source |
| `--no-deps` | Skip dependencies | Incomplete install |
| `pip install --user` | User site-packages | Same execution |
| Virtualenv | Isolated env | Same execution |

---

## Cargo / Rust

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `cargo build` | Build project | Yes (build.rs, proc-macro) |
| `cargo install` | Install binary | Yes (build.rs, proc-macro) |
| `cargo add` | Add dependency | Updates Cargo.toml |
| `cargo fetch` | Download deps | No (just downloads) |

### Execution Points
| Point | Mechanism | Risk |
|---|---|---|
| `build.rs` | Rust code at compile time | High |
| Proc-macros | Compiler plugins | High |
| Build-dependencies | Crates used during build | Medium |

### Dependency Sources
| Source | Example | Inspection |
|---|---|---|
| crates.io | `cargo add serde` | Registry scan |
| Git | `cargo add --git https://...` | Clone + scan |
| Path | `cargo add --path ../pkg` | Local scan |

### Inspection Strategy
1. **`cargo metadata`**: Get full dependency tree
2. **Scan Cargo.toml**: All dependencies + features
3. **Scan build.rs / proc-macros**: In each dependency
4. **Git dependencies**: Clone to temp, scan before build

### Bypass Analysis
| Bypass | Method | Mitigation |
|---|---|---|
| `/usr/bin/cargo` | Direct binary | Document |
| `--locked` | Use Cargo.lock | Still builds |
| Offline mode | Pre-fetched | Still executes build.rs |

---

## Go

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `go get` | Add dependency | Downloads + builds |
| `go build` | Build | Compiles (no arbitrary exec*) |
| `go generate` | Code generation | Yes (arbitrary commands) |
| `go install` | Install binary | Builds + installs |

### Execution Points
| Point | Mechanism | Risk |
|---|---|---|
| `go:generate` directives | Arbitrary commands | High |
| Build tags | Conditional compilation | Low |
| `//go:embed` | File embedding | Low |

*Go compilation itself doesn't execute arbitrary code like setup.py/build.rs, but `go generate` and `cgo` can.

### Dependency Sources
| Source | Example | Inspection |
|---|---|---|
| Proxy | `go get github.com/...` | Module cache scan |
| Git | Direct repo | Clone + scan |
| Local | `replace` directive | Local scan |

### Inspection Strategy
1. **`go list -m -json all`**: Full module graph
2. **Scan go.mod / go.sum**: Versions + hashes
3. **Check for `go:generate`**: In all modules
4. **Module cache scan**: `go mod download` then scan

### Bypass Analysis
| Bypass | Method | Mitigation |
|---|---|---|
| `/usr/bin/go` | Direct binary | Document |
| `GOPROXY=off` | Direct fetch | Still downloads |
| `go mod vendor` | Vendor dir | Scan vendor/ |

---

## RubyGems / Bundler

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `gem install` | Install gem | Yes (extconf.rb, Rakefile) |
| `bundle install` | Install from Gemfile | Yes (Gemfile, gemspec) |
| `bundle exec` | Execute in context | Runs command |

### Execution Points
| Point | Mechanism | Risk |
|---|---|---|
| `extconf.rb` | Ruby C extension config | High |
| `Rakefile` / `Gemfile` | Arbitrary Ruby | High |
| Native extensions | Compile C code | Medium |

### Inspection Strategy
1. **Scan Gemfile / gemspec**: Dependencies + sources
2. **Download gems**: `gem fetch` then scan
3. **Check for extensions**: `extconf.rb`, `Rakefile`, `Makefile`

---

## Composer / PHP

### Commands
| Command | Purpose | Executes Code |
|---|---|---|
| `composer install` | Install deps | Yes (scripts) |
| `composer require` | Add dependency | Yes (scripts) |
| `composer run-script` | Run script | Yes |

### Execution Points
| Point | Mechanism | Risk |
|---|---|---|
| `scripts` in composer.json | PHP/shell commands | High |
| `post-install-cmd` | After install | High |
| `post-update-cmd` | After update | High |

---

## Dependency Installation Coverage Matrix

| Manager | Config Files | Pre-Install Scan | Lifecycle Scripts | Git/URL Deps | Bypass Risk |
|---|---|---|---|---|---|
| npm | package.json, lock | ✅ (download + scan) | pre/install/post/prepare | ✅ | High |
| pip | pyproject.toml, setup.py | ✅ (wheel/sdist scan) | setup.py, build backend | ✅ | High |
| Cargo | Cargo.toml, lock | ✅ (metadata + scan) | build.rs, proc-macro | ✅ | High |
| Go | go.mod, go.sum | ✅ (mod cache scan) | go:generate, cgo | ✅ | Medium |
| gem/bundle | Gemfile, gemspec | ✅ (gem fetch) | extconf.rb, Rakefile | ✅ | High |
| composer | composer.json, lock | ✅ (download) | scripts | ✅ | High |

---

## Key Findings

1. **All major package managers execute arbitrary code during installation**
   - This is by design (build native extensions, run setup, etc.)
   - Not a bug - fundamental to how they work

2. **Pre-install scanning is feasible for all**:
   - Download/extract to temp directory
   - Scan with existing repository scanners
   - Then proceed with actual install if approved

3. **Lockfiles are critical**:
   - `package-lock.json`, `Cargo.lock`, `go.sum`, `composer.lock`
   - Ensure reproducible installs
   - Scan lockfile + verify hashes match

4. **Git/URL dependencies need special handling**:
   - Clone to temp first
   - Scan as repository
   - Then install from local path

5. **Global vs project installation**:
   - `npm install -g`, `pip install --user`, `cargo install`
   - Same execution, different target directory
   - Should still scan before install

---

## Practical Approach: Universal Package Manager Wrapper

### Architecture
```
User runs:  npm install
                │
                ▼
        ┌───────────────┐
        │ Detect PM +   │
        │ Repo Context  │
        └───────┬───────┘
                │
                ▼
        ┌───────────────┐
        │ Download to   │
        │ Temp + Scan   │
        └───────┬───────┘
                │
                ▼
        ┌───────────────┐
        │ Show Findings │
        │ Prompt Approve│
        └───────┬───────┘
                │
       ┌────────┴────────┐
       ▼                 ▼
   Approved           Cancelled
       │                 │
       ▼                 ▼
  Real PM Install    Block + Report
```

### Implementation Requirements
1. **Detect package manager**: argv[0] or command pattern
2. **Identify repository**: Walk up for package.json, Cargo.toml, pyproject.toml, etc.
3. **Create temp workspace**: Isolated from user files
4. **Download dependencies**: Use PM's download-only flags
   - npm: `npm pack` / `npm install --dry-run --json`
   - pip: `pip download` / `pip wheel`
   - cargo: `cargo fetch` + `cargo metadata`
   - go: `go mod download`
5. **Scan with existing scanners**: Reuse inventory + malware + security
6. **Present unified report**: Findings across all deps
7. **Execute real PM on approval**: Preserve all flags/args

### Bypass Documentation (Required)
Each wrapper must document:
- Direct binary bypass: `/usr/bin/<pm>`
- Environment variable bypasses
- Flags that skip execution: `--ignore-scripts`, `--no-build-isolation`
- Container/VM isolation

---

## Integration with Existing LinuxSecMonitor

The existing scanners already support:
- ✅ Repository inventory (file listing, manifests)
- ✅ Malware scanning (ClamAV on staged files)
- ✅ Security analysis (risky patterns, secrets, hooks)

**New components needed:**
1. **Package manager detection + argument parsing**
2. **Temp workspace management** (download, extract, scan, cleanup)
3. **PM-specific download logic** (each PM has different flags)
4. **Unified findings report** (merge scanner outputs for deps)
5. **Approval flow integration** (reuse execution_guard.confirm_execution)
5. **Real PM execution** (preserve argv, env, cwd)