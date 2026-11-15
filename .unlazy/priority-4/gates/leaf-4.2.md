# Gates: Installed-Wrapper Post-Clone Review Integration - 4.2

Status: COMPLETE.

Depends on completed P4.1 (installed wrapper lifecycle) and P3A.5 (Git clone parsing,
post-clone review, scanner/cache behavior, snapshot integrity, and approval semantics).

Scope: Verify the P4.1 installed Git wrapper reaches the existing P3A.5 post-clone review.
Do not duplicate or alter P3A.5 behavior. Git clone executes before post-clone review; this
work unit does not claim that clone execution itself is gated.

- [x] G1: Installed-route successful worktree clones
  CHECK: Focused installed-wheel tests using a clean temporary venv, temporary HOME, an
  offline local origin, and cwd outside the checkout cover explicit and derived destination.
  Exercise the installed `git` shim; verify real Git created each worktree, the installed
  P3A.5 scanner/review path observed the corresponding destination, and exact `RUN` accepted
  only that reviewed snapshot.
  EXPECT: Both clones complete and report post-clone snapshot acceptance; scanner event proves
  the reviewed root is exactly the resulting worktree.
  EVIDENCE: `python3 -m pytest -vv tests/test_wrapper_installed_wheel.py` — 27 passed in
  32.54s. `TestInstalledPostCloneReview::test_installed_shim_reviews_successful_worktree_clone`
  passed for explicit and derived destinations. Each test invokes the installed shim from a
  temporary venv/HOME and outside the checkout; local Git creates the worktree, the scanner
  event records its exact resolved root, and exact `RUN` reports acceptance.

- [x] G2: Exact post-clone acknowledgment
  CHECK: Through the installed shim and a controlling PTY, test `RUN`, `run`, `RUN `, empty
  input/EOF, and interrupt/cancellation.
  EXPECT: Only exact case-sensitive `RUN` accepts; every other input returns nonzero and does
  not report acceptance. Existing prompt wording and semantics remain unchanged.
  EVIDENCE: The same installed-wheel command passed 27 tests. Exact `RUN` acceptance is exercised
  by G1 and the approval-isolation test; `run`, `RUN `, empty line, EOF, and interrupt all return
  nonzero with the clone unaccepted. No P3A.5 prompt implementation was changed.

- [x] G3: Git failure and review fail-closed behavior
  CHECK: Through the installed shim, cover a deterministic failed local clone and deterministic
  incomplete coverage, scanner error, malware detection, content-hash mismatch, and no-TTY.
  EXPECT: Failed clone returns Git's exact nonzero status without invoking review. Every blocked
  or unavailable review returns nonzero, never accepts, and leaves the clone on disk as P3A.5
  specifies.
  EVIDENCE: The same installed-wheel command passed 27 tests. The failed-clone test compares the
  shim exit status with direct real-Git status and observes no scanner event. Installed-route
  cases for incomplete coverage, scanner error, malware, integrity mismatch, and missing TTY
  fail closed without acceptance; review-blocked clones remain on disk.

- [x] G4: Bare/mirror clones and approval isolation
  CHECK: Through the installed shim, cover `--bare` and `--mirror`, then attempt a separate
  protected Tier 1 command after an accepted worktree clone. Also run the focused P3A.5
  approval/cache regression selectors.
  EXPECT: Bare/mirror clones are not represented as reviewed or accepted worktrees. Clone
  acknowledgment creates no reusable `ApprovalManager` authorization; the later Tier 1 command
  still requires its own approval. P3A.5 cache invalidation and review semantics remain intact.
  EVIDENCE: The same installed-wheel command passed 27 tests; bare and mirror clones produce no
  scan/approval event and no worktree acceptance. The follow-up Tier 1 checkout remains blocked
  without its own controlling-terminal approval. The command
  `python3 -m pytest -vv tests/test_git_integration.py::TestCloneExecutionWorkflow tests/test_git_integration.py::TestCloneReviewFailClosed tests/test_git_integration.py::TestCloneReviewCaching tests/test_git_integration.py::TestPostCloneApprovalIsolation`
  passed 30 tests in 1.30s.

- [x] G5: Test isolation and focused regression
  CHECK: Installed-route tests use only temporary HOME/venv/local repositories, run outside the
  source checkout, and pass the primary-HOME RC guard. Run only the installed-wrapper clone
  tests and relevant P3A.5 selectors.
  EXPECT: No remote network dependency or primary user shell-configuration change; all stated
  P4.2 scenarios pass. No broad suite or unrelated gate reverification.
  EVIDENCE: All installed-route tests use the module's freshly built wheel/temporary venv,
  temporary HOME, temporary local origin and clone destination, and cwd outside the checkout;
  the imported `guard_primary_home_rc` autouse fixture protects primary-HOME RC metadata and
  hashes. The local fixtures make no remote clone requests. The installed-wheel and P3A.5
  focused commands above passed; no full suite, APT transaction, or broad audit was run.
