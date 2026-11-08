# Build System Coverage Analysis

## Make

### Execution Methods
| Method | Example | File Artifact | Pre-Exec Scan |
|---|---|---|---|
| Default target | `make` | Makefile | Yes |
| Specific target | `make install` | Makefile | Yes |
| Variables | `make PREFIX=/usr` | Makefile | Yes |
| Recursive | `make -C subdir` | Makefile(s) | Yes |
| Dry-run | `make -n` | Makefile | Shows commands |

### Make-Specific Risks
- **Arbitrary shell commands**: Any recipe line executes in shell
- **`$(shell ...)`**: Executes at parse time (before rules run)
- **`include`**: Can include arbitrary files/Makefiles
- **`-f`**: Alternate Makefile
- **`SHELL` variable**: Can change shell used
- **`.ONESHELL`**: Changes execution model
- **Recursive make**: Sub-Makefiles not visible to parent scan

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Static analysis of Makefile | High | Advisory |
| Wrapper `make` in PATH | Medium | Only if wrapper used |
| Parse `$(shell ...)` calls | Static | Advisory |
| eBPF on make `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/make` bypasses PATH
- `make -f /tmp/evil.mk` uses alternate Makefile
- `SHELL=/bin/bash` can be set in Makefile
- Recursive make invokes new make process

### Verdict
**Makefile statically analyzable; recursive/alternate Makefiles need separate scan.**

---

## CMake

### Execution Methods
| Phase | Commands | File Artifacts | Risk |
|---|---|---|---|
| Configure | `cmake -B build` | CMakeLists.txt | Generates build files |
| Build | `cmake --build build` | Build files | Compiles code |
| Install | `cmake --install build` | Install scripts | Copies files |
| Script | `cmake -P script.cmake` | .cmake file | Arbitrary CMake commands |

### CMake-Specific Risks
- **`execute_process()`**: Runs commands at configure time
- **`add_custom_command()`**: Runs commands at build time
- **`file(DOWNLOAD ...)`**: Downloads files
- **`find_package()`**: Can execute package scripts
- **`include()`**: Includes arbitrary .cmake files
- **`execute_process(COMMAND bash ...)`**: Shell execution
- **Generator expressions**: Complex logic at build time

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Static analysis of CMakeLists.txt | High | Advisory |
| Wrapper `cmake` in PATH | Medium | Only if wrapper used |
| Scan generated build.ninja / Makefile | Post-configure | Late |
| eBPF on cmake `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/cmake` bypasses PATH
- `cmake -P /tmp/evil.cmake` executes arbitrary CMake
- Toolchain files can execute commands
- ExternalProject_Add downloads and builds at configure time

### Verdict
**CMakeLists.txt analyzable; configure-time execution (`execute_process`) is a gap.**

---

## Cargo (Rust)

### Execution Methods
| Command | Artifacts | Risk |
|---|---|---|
| `cargo build` | Cargo.toml, src/ | Compiles Rust |
| `cargo run` | Cargo.toml, src/ | Builds + runs |
| `cargo test` | Cargo.toml, tests/ | Builds + runs tests |
| `cargo install` | crates.io / git / path | Downloads + builds |
| `cargo build --build-plan` | JSON output | Shows commands |

### Cargo-Specific Risks
- **`build.rs`**: Arbitrary Rust code executed at compile time
- **`proc-macro`**: Compiler plugins executing at compile time
- **`build-dependencies`**: Crates used during build (can execute)
- **`[package] metadata`**: Can contain arbitrary data
- **`cargo:rustc-env=`**: Sets env vars during build
- **Git dependencies**: Clones and builds from Git
- **Path dependencies**: Local crates

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Static analysis of Cargo.toml | High | Advisory |
| Scan `build.rs` / proc-macros | High | Advisory |
| Wrapper `cargo` in PATH | Medium | Only if wrapper used |
| `cargo metadata` JSON | High | Advisory |
| eBPF on cargo/rustc `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/cargo` bypasses PATH
- `cargo install --git` clones and builds
- Build scripts run with full user privileges
- Proc-macros are compiler plugins (hard to sandbox)

### Verdict
**Cargo.toml and build.rs analyzable; build-time execution is fundamental to Rust compilation.**

---

## npm / Node.js Build

### Execution Methods
| Command | Artifacts | Risk |
|---|---|---|
| `npm run build` | package.json scripts | Arbitrary shell |
| `npm run <script>` | package.json | Arbitrary shell |
| `npx cmd` | Package binaries | Downloads + executes |
| `npm ci` | package-lock.json | Clean install |

### npm-Specific Risks
- **Lifecycle scripts**: `preinstall`, `install`, `postinstall`, `prepare`, `prepublishOnly`, `prepack`, `postpack`
- **`scripts` in package.json**: Arbitrary shell commands
- **`npx`**: Downloads and executes packages
- **Workspaces**: Multiple package.json files
- **`npm exec`**: Executes package commands

### Inspection Points
| Point | Feasibility | Can Block |
|---|---|---|
| Static analysis of package.json | High | Advisory |
| Scan all workspace package.json | High | Advisory |
| Wrapper `npm` in PATH | Medium | Only if wrapper used |
| `npm pack` dry-run | Medium | Shows files |
| eBPF on npm/node `execve` | High | Yes |

### Bypass Analysis
- Direct `/usr/bin/npm` bypasses PATH
- `npm install --ignore-scripts` skips lifecycle (but user must know)
- `npx` bypasses local package.json
- Workspaces: multiple manifests

### Verdict
**package.json scripts fully analyzable; this is the highest-value interception point.**

---

## Other Build Systems

### Meson
- `meson setup build` - meson.build files
- `meson compile -C build` - ninja backend
- `meson.build` analyzable; can execute `run_command()`

### Bazel
- `bazel build //...` - BUILD/WORKSPACE files
- Starlark language (Python-like) - can execute at load time
- Hermetic but complex

### Gradle
- `gradle build` - build.gradle (Groovy/Kotlin DSL)
- Arbitrary code execution in build script
- `gradle --dry-run` shows task graph

### Autotools
- `./configure` - generated script, executes tests
- `make` - Makefile.am → Makefile.in → Makefile
- `configure.ac` analyzable; `configure` script not

### SCons
- `scons` - SConstruct/SConscript (Python)
- Full Python execution at build definition time

### GNUMake / BSD Make
- Same as Make analysis

---

## Build System Coverage Matrix

| Build System | Config Files | Pre-Build Scan | Build-Time Exec | Lifecycle Hooks | Bypass Risk |
|---|---|---|---|---|---|
| Make | Makefile | ✅ | ⚠️ $(shell) | No | High (alt Makefile) |
| CMake | CMakeLists.txt | ✅ | ⚠️ execute_process | No | High (cmake -P) |
| Cargo | Cargo.toml, build.rs | ✅ | ⚠️ build.rs, proc-macro | build-dependencies | High (git deps) |
| npm | package.json | ✅ | ⚠️ lifecycle scripts | pre/post install | High (npx, --ignore-scripts) |
| Meson | meson.build | ✅ | ⚠️ run_command | No | Medium |
| Bazel | BUILD, WORKSPACE | ⚠️ Starlark | ⚠️ load-time exec | No | High |
| Gradle | build.gradle | ✅ | ⚠️ Groovy/Kotlin DSL | Task hooks | High |
| Autotools | configure.ac | ✅ | ⚠️ configure script | No | High |
| SCons | SConstruct | ✅ | ⚠️ Full Python | No | High |

---

## Key Findings

1. **All build systems have configuration files that are statically analyzable**

2. **Build-time execution is fundamental, not optional**:
   - Make: `$(shell ...)`
   - CMake: `execute_process()`
   - Cargo: `build.rs`, proc-macros
   - npm: lifecycle scripts
   - Gradle: DSL is executable code
   - Bazel: Starlark at load time
   - SCons: Python at definition time

3. **Configuration-time execution is a blind spot**:
   - CMake `execute_process()` runs during `cmake configure`
   - Cargo `build.rs` runs during compilation
   - These execute **before** the actual build commands

4. **Dependency fetching executes code**:
   - `cargo install --git` clones and builds
   - `npm install` runs lifecycle scripts
   - `go get` downloads and builds modules
   - `pip install` runs setup.py / build backend

5. **Generated build files are late artifacts**:
   - CMake generates `build.ninja` or `Makefile` after configure
   - These can be scanned but only after configure-time execution

---

## Practical Approach

### Pre-Build Scan (Static)
1. **Scan all configuration files** on directory entry:
   - Makefile, CMakeLists.txt, Cargo.toml, package.json, meson.build, build.gradle, etc.
2. **Flag dangerous patterns**:
   - Make: `$(shell`, `include`, `SHELL=`
   - CMake: `execute_process`, `file(DOWNLOAD`, `add_custom_command`
   - Cargo: `build.rs`, `proc-macro`, `build-dependencies`
   - npm: `scripts`, `preinstall`, `install`, `postinstall`, `prepare`
   - Gradle: `exec`, `javaexec`, `ant`, custom tasks
3. **Report findings before any build command runs**

### Build Command Wrappers
```
User runs:  make
Wrapper:    Scans Makefile, shows findings, prompts if risky
            If approved: exec real make
```

### Package Manager Interception (Highest Priority)
- Intercept `npm install`, `cargo install`, `pip install`, `go get`, `gem install`, `composer install`
- Download to temp, scan, then install with approval
- This catches the most dangerous execution vector

### Known Bypasses (Documented)
- Direct binary paths: `/usr/bin/make`, `/usr/bin/cmake`, etc.
- Alternate config: `make -f`, `cmake -P`, `cargo --manifest-path`
- Environment variables to skip: `npm_config_ignore_scripts`, `CARGO_BUILD_SCRIPTS=0`
- Container/VM isolation