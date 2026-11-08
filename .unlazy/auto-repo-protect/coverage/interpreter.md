# Interpreter Execution Coverage Analysis

## Python

### Execution Methods
| Method | Example | File Artifact | Pre-Exec Scan Possible |
|---|---|---|---|
| Script file | `python script.py` | Yes (script.py) | Yes |
| Module | `python -m module` | Yes (module/__init__.py) | Yes |
| Inline code | `python -c "code"` | No | No |
| stdin | `python < script.py` | Yes (via stdin) | No (stream) |
| Interactive | `python` (REPL) | No | N/A |
| Shebang | `./script.py` | Yes | Yes |

### Python-Specific Risks
- **`eval()` / `exec()` / `compile()`**: Dynamic code execution from strings
- **`__import__()` / `importlib`**: Dynamic module loading
- **`subprocess` / `os.system`**: Shell command execution
- **`sitecustomize.py` / `usercustomize.py`**: Auto-executed on startup
- **`.pth` files**: Modify `sys.path` and can execute code
- **`PYTHONPATH` / `PYTHONSTARTUP`**: Environment-controlled behavior
- **Virtual environments**: Isolated but still execute user code
- **`pip install` / `python setup.py`**: Execute arbitrary code during install

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Wrapper `python` in PATH | Medium | Only if wrapper used |
| `sys.path` modification detection | Static analysis | Advisory |
| Bytecode cache (`.pyc`) scanning | Post-execution | No |
| eBPF on python `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/python3` bypasses PATH
- `python -c` no file to scan
- Virtualenv activation modifies PATH before wrapper
- `exec(open("x.py").read())` - reads file at runtime

### Verdict
**Script files scannable; inline/REPL/dynamic execution not interceptable at user level.**

---

## Node.js

### Execution Methods
| Method | Example | File Artifact | Pre-Exec Scan Possible |
|---|---|---|---|
| Script file | `node script.js` | Yes | Yes |
| Inline | `node -e "code"` | No | No |
| REPL | `node` | No | N/A |
| Module | `node -m module` | Yes | Yes |
| stdin | `node < script.js` | Yes (stream) | No |
| npx | `npx cmd` | Package bin | Package scan |

### Node.js-Specific Risks
- **`eval()` / `Function()` / `vm` module**: Dynamic code execution
- **`require()` / `import()`**: Dynamic module loading (including from URLs)
- **`child_process`**: Spawn shell commands
- **`require('child_process').execSync()`**: Synchronous shell exec
- **npm lifecycle scripts**: `preinstall`, `install`, `postinstall`, `prepare`
- **`node-gyp`**: Compiles native addons (executes Python, make)
- **`.node` native addons**: Binary modules, not scannable as source

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Wrapper `node` in PATH | Medium | Only if wrapper used |
| `package.json` scripts scan | Static analysis | Advisory |
| `node_modules` scan | Post-install | Late |
| eBPF on node `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/node` bypasses PATH
- `node -e` no file to scan
- `npx` downloads and executes packages
- Dynamic `require()` at runtime

### Verdict
**Script files and package.json scannable; inline/dynamic require not interceptable.**

---

## Other Interpreters

### Perl
- `perl script.pl` - file scannable
- `perl -e "code"` - no file
- `CPAN` modules - execute during install
- `eval` - dynamic execution

### Ruby
- `ruby script.rb` - file scannable
- `ruby -e "code"` - no file
- `gem install` - executes code during install
- `bundler` - executes Gemfile code
- `eval` - dynamic execution

### PHP
- `php script.php` - file scannable
- `php -r "code"` - no file
- `composer install` - executes scripts
- `eval()` - dynamic execution

### Deno / Bun
- Similar to Node.js
- Deno: permissions model (can restrict file/net/process)
- `deno run` - can use `--allow-read` etc.

### Lua / Perl / Tcl / etc.
- Same patterns: file scannable, inline not

---

## Interpreter Coverage Matrix

| Interpreter | File Scripts | Inline (-c/-e) | REPL | Package Install | Dynamic Load | Shebang |
|---|---|---|---|---|---|---|
| Python | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Executes code | ❌ Runtime | ✅ Scan |
| Node.js | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Lifecycle scripts | ❌ Runtime | ✅ Scan |
| Perl | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ CPAN | ❌ Runtime | ✅ Scan |
| Ruby | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Gem/Bundler | ❌ Runtime | ✅ Scan |
| PHP | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Composer | ❌ Runtime | ✅ Scan |
| Deno | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Imports | ❌ Runtime | ✅ Scan |
| Bun | ✅ Scan | ❌ No file | ❌ N/A | ⚠️ Package.json | ❌ Runtime | ✅ Scan |

---

## Key Findings

1. **All interpreters: File-based scripts are scannable; inline code is not**

2. **Package installation executes arbitrary code** - this is the highest-risk vector:
   - `pip install` → `setup.py` / `pyproject.toml` build backend
   - `npm install` → `preinstall`/`install`/`postinstall` scripts
   - `gem install` → native extensions, scripts
   - `composer install` → scripts

3. **Dynamic module loading at runtime cannot be pre-scanned**
   - Python: `importlib.import_module()`, `__import__()`
   - Node: `require()`, dynamic `import()`
   - Ruby: `require`, `load`
   - These can load code from arbitrary paths/URLs at runtime

4. **Virtual environments / isolated environments don't prevent execution**
   - They isolate dependencies, not execution
   - Code still runs with user's privileges

5. **Deno's permission model is unique** - can restrict at runtime:
   - `--allow-read`, `--allow-write`, `--allow-net`, `--allow-run`
   - But requires user to invoke with flags

---

## Practical Approach

### For File-Based Scripts (All Interpreters)
- **Scan on directory entry** (shell hook detects repo, scans scripts)
- **Static analysis of package manifests** (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`)
- **Warn on dangerous patterns** (lifecycle scripts, dynamic imports, eval)

### For Package Installation
- **Intercept package manager commands** (`pip`, `npm`, `yarn`, `pnpm`, `cargo`, `gem`, `composer`, `go get`)
- **Scan package contents before install** (download to temp, scan, then install)
- **Require approval for packages with lifecycle scripts**
- **This is the highest-value interception point**

### For Inline/Dynamic Execution
- **Cannot pre-scan** - no persistent artifact
- **Runtime monitoring** (eBPF, auditd) could detect suspicious behavior post-facto
- **Document as known limitation**

### Shell Wrapper Strategy
```
User runs:  npm install
Wrapper:    Detects repo, scans package.json, checks for lifecycle scripts
            If risky: show findings, prompt for approval
            If approved: exec real npm install
```

**Acceptable bypasses documented:**
- Direct binary: `/usr/bin/npm install`
- Environment: `npm_config_ignore_scripts=true`
- Container/VM: Different environment