# Changes to WIN11STIG

## Based on STIG v2.9.0 - ALD Windows Alignment Updates

### check_mode safety

- FIXED: **two tasks modified the host during `--check`.** `check_mode: false` makes a task run in
  a check pass, so `WN11-00-000105` ran `takeown` and `icacls` against
  `C:\Windows\System32\snmp.exe` and `WN11-00-000140` ran `Remove-NetFirewallRule`, on a run the
  operator had asked to change nothing. Both annotations are removed so check mode skips them, and
  the consumer of the SNMP register now reads `.stdout | default('', true)`, since a skipped task
  leaves no `stdout` and the bare reference would fail the play. Neither was reachable on a default
  run: the first needs the SNMP binary present, the second needs
  `win11stig_remove_unauthorized_hosts: true`.

- FIXED: **the two `WN11-00-000085` audit tasks reported changed on every run.** Both only read
  local accounts, but neither declared `changed_when: false`. They now do.

- FIXED: **two more paths broke `--check`, one by failing and one by changing the host.** The pre
  remediation audit was not gated on check mode the way the post remediation audit was, so a
  `--check` run with `setup_audit` reached the staging tasks, `win_file` reported the working
  directory created without creating it, and the ACL task that followed failed the play on a path
  that was never made. Separately, `prelim.yml` does not load registry hives under `--check` but
  `unload_hives.yml` ran anyway, and every task in it carries `check_mode: false`. With the
  baseline facts that the subtraction depends on never set, the expression collapsed to "every
  mounted hive named `DEFAULT`", so a check run unloaded a hive it had not mounted and a
  signed-in user could lose their profile mid-session. The audit import now carries the same
  check mode condition as its post remediation counterpart, and the unload guard sits at the top
  of `unload_hives.yml` rather than at the call site, so a future caller cannot omit it.

### Domain membership detection

- FIXED: **the role assumed domain joined whenever the membership fact was missing.**
  `discovered_domain_joined` is seeded `true` and `prelim.yml` only overwrites it
  `when: ansible_facts['windows_domain_member'] is defined`, so on any run that did not gather that
  fact the seeded value stood and roughly 40 gates across the role behaved as though the host were
  domain joined. Standalone-only branches never ran and domain-only settings were applied to
  standalone hosts. `prelim.yml` now gathers the `windows_domain` subset itself when the fact is
  absent, so the value is established rather than assumed.

- CHANGED: **`discovered_domain_joined` now defaults to `false`.** With the gather above in place
  the seeded value is only reached when membership genuinely cannot be determined, and treating
  such a host as standalone is the safer reading: standalone controls apply and domain-only
  settings do not. This is a behaviour change for any run where the fact is unavailable, which is
  why it is a separate commit from the gather. Matches the three Windows Server roles.

- `README.md`: added a `Domain Members` section documenting that account policy is domain scoped,
  with the values measured on a domain joined workstation against the STIG targets, and the
  instruction to set them in the Default Domain Policy instead.

### Defects found on a live domain joined workstation

- FIXED: **the per-user controls wrote to a hive no real user reads.** `win_regedit` with an
  `HKCU:` path resolves to the hive of the account Ansible authenticated as, so `WN11-UC-000015`,
  `WN11-UC-000020`, `WN11-CC-000390` and the Copilot control in `WN11-00-000125` left their
  settings in the automation account's profile, where they take effect for nobody, while each task
  reported changed. `prelim.yml` now loads the Default profile and every user hive listed in
  `ProfileList`, those controls write to `HKU:\<sid>\` for each loaded hive, and the new
  `unload_hives.yml` releases only the hives the role itself loaded. `ProfileList` rather than
  `Win32_UserAccount`: the latter returns local accounts only, so a domain account holding a
  profile on the machine was skipped and its hive left unset. A benchmark scan of a remediated
  host confirmed the three that it had reported open now pass. The hive list those controls loop
  is the set this role mounted, not every key under `HKEY_USERS`: that always carries `.DEFAULT`
  and the service SIDs `S-1-5-18`, `S-1-5-19` and `S-1-5-20`, which the profile enumeration
  already filters out, and writing per-user policy into them reaches no real user. `.DEFAULT` is
  an alias for `S-1-5-18`, so the unfiltered list also wrote one hive twice. Set
  `win11stig_load_user_hives: false` to skip the per-user controls instead of applying them
  ineffectively.

All five were found by running the role against a domain member and are host proven. None of
them are reachable by `ansible-lint`, `yamllint` or `--syntax-check`; each only fails at runtime.
Each was found by the run that verified the one before it.

- FIXED: **WN11-00-000140 aborted the play on the ordinary configuration.**
  `discovered_00_000140_firewall_installed` is set by a task that is itself behind a `when`, then
  referenced bare by the next task's `when`. The check keys off
  `Get-CimInstance root\SecurityCenter2 FirewallProduct`, which enumerates third party firewall
  products only, so a host running nothing but Windows Defender Firewall returns an empty set, the
  guarded `set_fact` is skipped, and the run stops with
  `'discovered_00_000140_firewall_installed' is undefined`. That is the common case, not an edge
  case: the test host returned `count=0`.

  The variable and its three siblings are now seeded in `vars/main.yml`, so a skipped `set_fact`
  falls back to a safe value instead of leaving the name undefined. `WN11-00-000190` keeps its
  guard, because its `set_fact` runs the output through `from_json` and that fails on an empty
  string; the seeded default is what makes that guard safe. A sweep for the same shape -
  conditionally set, no default, referenced bare in a `when` - returns **zero** remaining.

- FIXED: **WN11-CC-000037 severed the control connection mid-run.** It writes
  `LocalAccountTokenFilterPolicy=0`, which filters the privileged token of local accounts on
  network logon. A run connected over WinRM or psrp as a local administrator loses the host as the
  control applies. It presents as `the specified credentials were rejected by the server` rather
  than as a dropped connection, because the port keeps answering and the service keeps running -
  on the test host 5985, 5986 and 22 all still accepted TCP after the play went UNREACHABLE.

  The control now carries `not win_skip_for_test`, and is listed with the other connection
  severing controls in `defaults/main/main.yml`. It is **also** skipped automatically whenever the
  run is a local account over a network logon transport, whatever `win_skip_for_test` is set to,
  from a new `discovered_local_account_network_logon` fact in `prelim.yml`. The operator is warned
  once and the warning is counted through `warning_facts.yml`. A domain account is exempt and SSH
  does not use that logon path, so either lets the control apply normally.

- FIXED: **WN11-SO-000251 aborted the play on a bad expression.** It tested
  `register.values | length`, but `ansible.windows.win_reg_stat` returns `exists`, `properties`
  and `sub_keys` and has no `values` field. Because the register is a dictionary, `.values`
  silently resolves to the Python dictionary method rather than raising a missing key error, so
  the mistake only surfaces when a filter is applied to it:
  `object of type 'method' has no len()`. Verified against the module's real output on a host.

  Now tests `sub_keys`, which is what "populated" means for `Calais\Readers` and
  `Calais\SmartCards` - both carry one sub-key per reader or card. The six `.stdout_lines`
  references on the same two registers, which also do not exist on a `win_reg_stat` result and
  would have failed had the compliance branch been reached, are corrected in the same way.

- FIXED: **WN11-UR-000070 severed both transports at once.** Found by the run that verified the
  three fixes above: with `WN11-CC-000037` correctly skipped, the play still went UNREACHABLE, 129
  tasks later than before. The domain member branch sets `SeDenyNetworkLogonRight` to include
  `Local account`, which removes the network logon right from every local account on the host,
  including the one the run is connected as.

  This one is worse than `WN11-CC-000037` and needs stating plainly: **no remote transport is a
  fallback for it.** Every lifeline was tried against the host after it applied, and all six
  failed:

  | Transport | Principal | Result |
  |---|---|---|
  | WinRM password | local | credentials rejected |
  | WinRM password | domain admin | credentials rejected |
  | SSH password | local | connection reset at the auth packet |
  | SSH public key | local | connection reset at the auth packet |
  | SSH public key | domain admin | connection reset at the auth packet |
  | WinRM certificate | local, mapped | TLS and cert mapping succeed, then HTTP 500 wsmanfault 1309, "an attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client" |

  Two of those are worth keeping. **SSH public key authentication does not survive it either** -
  Windows OpenSSH builds its pubkey logon through the same network logon path, so sshd answers,
  negotiates protocol and then resets. And **certificate authentication gets furthest without
  helping**: the handshake and the account mapping both succeed, and it fails at the impersonation
  token, which is the clearest single piece of evidence that this is a logon right problem rather
  than a credential or transport one.

  Throughout, 5985, 5986 and 22 all still accepted TCP and sshd still returned its version banner.
  Only authentication was refused. The console was the only way back in.

  The control now carries `not win_skip_for_test`, is listed with the other connection severing
  controls in `defaults/main/main.yml`, and is skipped automatically whenever the run connects as a
  local account, from a new `discovered_control_account_is_local` fact. The non-domain branch,
  which sets the right to `Guests` alone, is untouched.

  Note which principals actually survive it, because it is narrower than it first looks. The right
  is set to `Guests, Enterprise Admins, Domain Admins, Local account`, so a **Domain Admin is
  denied by this control too** - being a domain principal is not sufficient. Confirmed against the
  test host: after the control applied, a domain admin account was refused in all three principal
  forms, exactly as the local account was. The connection that survives is a domain account that is
  neither a Domain Admin nor an Enterprise Admin, and that is a member of the local Administrators
  group on the target. The automatic guard cannot detect the Domain Admin case, since that needs a
  group membership query the role does not make, so the warning names the requirement instead.

  The two facts are deliberately separate: `discovered_control_account_is_local` is about the
  principal and applies on any transport, while `discovered_local_account_network_logon` adds the
  transport test and is what `WN11-CC-000037` needs. Collapsing them into one would either leave
  `WN11-UR-000070` able to sever an SSH run, or stop `WN11-CC-000037` applying over SSH where it is
  perfectly safe.

- FIXED: **WN11-UR-000075 and WN11-UR-000080 halted the play on an invalid group name.** Both
  passed `Enterprise Admin` and `Domain Admin` to `ansible.windows.win_user_right`. Neither is a
  group name - the Active Directory groups are `Enterprise Admins` and `Domain Admins` - so on a
  domain joined host the module fails with `Failed to translate the account 'Enterprise Admin' to
  a SID` and the run stops. `WN11-UR-000070` in the same file already used the correct plurals,
  which is why it applied cleanly while these two did not.

  Found by the hardening run that verified the four fixes above, on a rolled back host. A sweep of
  every account name passed to `win_user_right` across the role now returns nine distinct names,
  all valid: Administrators, Domain Admins, Enterprise Admins, Guests, LOCAL SERVICE, Local
  account, NETWORK SERVICE, SERVICE, Users. No singular forms remain.

- NOTE: the detection for the control connection builds its backslash from a YAML single quoted
  variable rather than a Jinja literal. In a Jinja expression neither `'\'` nor `'\\'` matches one
  backslash in this position - the first is a syntax error, the second tests for two - so
  `DOMAIN\user` went undetected. The YAML form takes the character literally and never reaches
  Jinja's string parser. Checked against NETBIOS, UPN and local account names over WinRM, psrp and
  SSH.

- `README.md`: added the `Compliance facts` section, which the Windows Fleet already carried and this role did not. It documents where the facts
  file is written, that Windows collects no local facts by default so `fact_path` must be passed
  explicitly, and that the result appears as `ansible_compliance_facts` rather than under
  `ansible_local`. The Windows Fleet now carries an identical section.

- CHANGED: the compliance facts file is now JSON. `templates/compliance_facts.ps1.j2` is replaced by
  `templates/compliance_facts.json.j2`, and the role writes
  `C:\ProgramData\ansible\facts.d\compliance_facts.json` instead of `...\compliance_facts.ps1`.
  This aligns the ALD Windows roles on a single facts format. The
  file is now parsed rather than executed to produce the fact.

  **The fact name and its keys are unchanged.** `ansible.windows.setup` builds the key from the
  file's `BaseName`, so it is still `ansible_compliance_facts`, and the five existing keys plus the
  conditional `Cat_N_tag_run` entries keep their names and meanings. Anything already reading this
  fact continues to work.

  Every value goes through `| to_json`, so the CAT toggles are now real JSON booleans rather than
  PowerShell `$true` / `$false`. The conditional tag entries use a leading comma, because a trailing
  comma after `cat_3_hardening_enabled` would emit invalid JSON on the default untagged run.

- ADDED: a task removing a superseded `compliance_facts.ps1` before the new file is written. Both
  extensions are collected and both produce the same fact key, so on a host hardened by an earlier
  release the stale file would otherwise be a second source for `ansible_compliance_facts` with no
  guaranteed precedence.

- ADDED: a `managed_by` key. The PowerShell file opened with a "managed by ansible" comment banner
  and JSON cannot hold comments, so that provenance is recorded as a field instead of being lost. Its
  value is derived from `file_managed_by_ansible`, so the wording stays in one place and the variable
  remains in use.

- `win_template` now sets `newline_sequence: "\r\n"`, so the file is written with CRLF line endings.
  **Not executed.** No Windows inventory was available, so the file is never actually collected by
  `ansible.windows.setup` here. The reasoning about fact naming comes from reading the module source.
  The rendered output was validated offline against all eight CAT tag combinations.

### Breaking changes

- BREAKING: `discovered_cloud_based_system` and `win11stig_cloud_vendors` are removed. Setting either
  in inventory, group_vars or extra vars is now **silently ignored** rather than raising an error.
  They existed only to choose between two implementations of the account lockout trio
  (`WN11-AC-000005`, `WN11-AC-000010`, `WN11-AC-000015`), and those two copies had converged on
  writing the same keys in the same order, so the choice no longer changed anything. The
  `cat2_cloud_lockout_order` **tag is also gone**; a run selecting it now matches nothing.

### Account policy scope and lockout ordering

- FIXED: the thirteen `[System Access]` controls written with `community.windows.win_security_policy`
  are now skipped on a domain joined host, gated on a new `discovered_account_policy_is_domain_scoped`
  fact set in `prelim.yml`. On such a host the Default Domain Policy owns that section and overwrites
  it at every policy refresh, so a local write reverted within roughly two hours while the run
  reported success, and an audit taken straight afterwards reported a compliance that did not last.
  The operator is warned once and the warning is counted through `warning_facts.yml`. The thirteen are
  the lockout trio, `AC-000020` through `AC-000045`, and `SO-000010`, `SO-000020`, `SO-000025` and
  `SO-000140`.
- The new fact is keyed on the observed `ansible_facts['windows_domain_member']`, deliberately not on
  `discovered_domain_joined`, which defaults to `true`. Keying it on that default would have skipped
  all thirteen controls on any host where the fact was missing.
- REMOVED: `tasks/cat2_cloud_lockout_order.yml`. The lockout trio now has a single implementation in
  `tasks/Cat2/WN11-AC-xxxxxx.yml`, still ordered `LockoutBadCount` -> `LockoutDuration` ->
  `ResetLockoutCount`. That order is load bearing and the reason is recorded in the file: secedit
  rejects the other two before a bad-count threshold exists, and rejects a reset counter greater than
  the current duration.
- The lockout trio now also honours `win_skip_for_test`, in line with the rest of the ALD Windows fleet. Changing
  the lockout threshold and duration mid-run can lock out the account Ansible is connected as.
- `prelim.yml` reads `ansible_facts['windows_domain_member']` rather than the bare
  `ansible_windows_domain_member`. `INJECT_FACTS_AS_VARS` is deprecated and removed in ansible-core
  2.24, so the bare form stops resolving.

  **Not executed.** No Windows inventory and no domain joined host was available, so the
  domain-scoped behaviour is statically verified, not exercised against a host.

- FIXED: `WN11-CC-000052` now honours `win_skip_for_test`. The control writes
  `EccCurves = NistP384 NistP256` to
  `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`, which
  reconfigures the Schannel curve list that the WinRM TLS connection itself depends on. Schannel
  policy applies to new connections, and Ansible opens a fresh request per task, so the handshake
  failed on the *following* task: the Azure pipeline run reported
  `ssl: ('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))` against
  `WN11-CC-000055` with `ok=251 changed=68 unreachable=1 failed=0`. The control that reported the
  failure was not the control that caused it. This is the same class as `WN11-SO-000230`, the
  FIPS-algorithms control, which was already guarded for the same reason. The documented skip list in
  `defaults/main/main.yml` is updated, and its introduction no longer describes the list as WinRM
  host controls alone, since it now covers the TLS and crypto policy the connection relies on.
  Note the tradeoff: with `win_skip_for_test: true` this control is not exercised by the pipeline.

- `README.md`: removed four controller-side dependencies the role does not use. It declared
  `passlib`, `python-lxml`, `python-xmltodict` and `python-jmespath`, and a paragraph describing an
  OpenSCAP tool installation. This role calls only `ansible.windows`, `community.windows` and
  `ansible.builtin` modules: there is no `password_hash` filter, no `xml` module, no `json_query`
  filter and no OpenSCAP task anywhere in it. `pywinrm` is retained and now carries the note, since
  it is the controller-side connection library. The only XML in the role is PowerShell
  `Get-AppLockerPolicy -Effective -XML` running on the target, which implies nothing about
  controller packages.
- `README.md`: brought the stale content in line with the Windows Fleet. The Ansible
  requirement read "tested against Ansible version 2.10.1 and newer" while `meta/main.yml` declared
  `2.16.1` and a `Local Testing` block claimed `2.18.2`; it now states the floor the role asserts in
  `tasks/main.yml`, and the `Local Testing` block is removed. The NIST tag documentation claimed all
  references are prefixed `NIST SP`, a form that appears zero times against 675 tags beginning
  `NIST`. The `800-53 Revision 4` conversion example rendered a non-R4 tag. Also a lowercase "stig",
  a stray double space, and "a clean install of the Windows 11".

- `README.md`: the `Release Tag` and `Closed Issues` badge URLs used a redundant double ampersand
  (`&&color=success`). Corrected to a single `&`, matching the Windows Fleet. Every role now carries an identical badge block.
  Also dropped the commented-out Ansible Galaxy Quality badge: it carried project ID `61846`, the
  same ID the Win-10 role used, so it was wrong in one of the two and rendered nothing either way.

- FIXED: `.yamllint` now ignores `.ansible/`, matching the Windows Fleet. The QA gate runs
  the checker twice, and the first run's internal `ansible-lint` installs
  `collections/requirements.yml` into `.ansible/collections/`. `yamllint` then walked that tree on
  the second run and linted several hundred vendored `ansible.windows` and `community.windows` files
  against this role's style rules, so the second run failed while the first passed. The gate is now
  order-independent. Only dependency code is excluded: role YAML is still linted.

### Breaking changes

- BREAKING: the two security tunables that still carried the legacy `wn11stig_` prefix are renamed
  to `win11stig_`, so every role behaviour variable and security tunable in this role now shares one
  prefix, matching the Windows Fleet. An override left under the old name is **silently ignored** rather
  than raising an error, so rename it in inventory, group_vars or extra vars:

  - `wn11stig_internet_based_apps_to_check` becomes `win11stig_internet_based_apps_to_check`
  - `wn11stig_pass_age_administrator` becomes `win11stig_pass_age_administrator`

  Rule toggles are untouched and keep the `wn11_<control id>` form. Beyond consistency, this brings
  both variables into scope for the QA gate's unused-variable check for the first time: neither
  invocation the gate makes could match the legacy prefix, so a typo in either name went unreported.

### Repository hygiene

- ADDED: **badge export, benchmark tracking and promotion reminders.**
  `export_badges_private.yml` and `benchmark_tracking_controller.yml` call the shared workflows the
  Linux roles already use, so this role's badges are published alongside theirs. A push to
  `latest` carrying a benchmark version not yet public opens a 90-day promotion tracker, once per
  version. Promotion is manual; the shared workflow sends reminders only.

- REMOVED: **the first-contributor welcome job.** It ran on a GitHub-hosted runner and posted a
  greeting to first-time contributors, which a private repository with approved contributors only
  does not have. The Azure validation job is unchanged.

- ADDED: **the role can now measure the host as well as harden it.** With `run_audit` it scans
  with SCAP Compliance Checker before and after remediation, and `audit_only` scans without
  applying anything. Both are off by default, alongside `setup_audit` to stage the scanner and
  `fetch_audit_output` to collect the result sets, so a plain hardening run is unchanged. The
  shape follows the rest of the fleet: settings in `defaults/main/audit.yml`, stages in
  `pre_remediation_audit.yml`, `post_remediation_audit.yml` and `fetch_audit_output.yml`. Results
  are read from the scanner's CKLB output, so findings are keyed by control ID and map directly
  onto the task that addresses them. Both scans run rather than only the second, because a
  post-remediation score on its own cannot separate a role that fixed findings from a host that
  was already compliant. `audit_only` ends the run for the host that finished scanning and not
  for the play, so a scan across an inventory measures every host rather than stopping at the
  first. `docs/README_SCC_QuickStart.md` covers the command line traps, the profile choice, the
  manual checks and the difference between domain joined and standalone results.

- FIXED: **the scanner was downloaded and executed without an integrity check.** The bundle is
  roughly 108 MB of third-party binaries staged onto a host the role is hardening, and the
  checksum was left optional on the stated grounds that no published digest existed. DISA does
  publish one, for every artifact in the release, at
  `https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_<version>_Checksums.txt`. The
  SHA-256 for the 5.15 Windows bundle is now pinned by default and confirmed against a downloaded
  copy of the archive. `win_get_url` enforces it even when the file is already on disk, verified
  by feeding it a wrong digest. Bumping `scc_version` without re-pinning now fails the run, which
  is the intended behavior.

- FIXED: **both validation pipelines could collide on the shared runner.** Neither declared a
  `concurrency` group, so two pull requests opened close together each reached `tofu apply` and
  raced over OpenTofu state and cloud resources. Both now declare two groups, because the two
  collisions want opposite handling. At workflow level a per pull request group cancels a run the
  operator has already superseded. At job level the group holding `tofu apply` is constant across
  the repository and does not cancel, so a second pull request queues behind the one holding the
  state rather than being cancelled mid-apply and stranding an Azure instance. A single per pull
  request group cannot do this: it gives every pull request its own lane, which is the collision
  being fixed. Separately, the credentials staged into `sensitive_info.json` were written with an
  appending redirect and never removed, leaving them on a persistent runner until the next
  checkout cleaned the workspace, and producing malformed JSON if the file ever survived into a
  second write. The redirect truncates and the file is deleted alongside the teardown.

- CHANGED: **`site.yml` names its play.** The play was anonymous and carried
  `# noqa: name[play]` to silence the lint rule rather than satisfy it. It is now
  `Run Windows 11 STIG Benchmark` and the suppression is gone, matching the play shape used
  elsewhere in the fleet. `vars: is_container: false` is removed with it: no task, template,
  default or workflow in this repository reads that variable, which is a Linux role idiom that
  arrived with the layout.

- CHANGED: **`meta/main.yml` declares the Galaxy role name as `windows_11_stig`, not
  `windows11_stig`.** The current convention across the Windows Fleet is
  `windows_<version>_<benchmark>`, used by the other STIG roles and by the CIS roles. This role is
  not yet published, so the name is still free; a sibling that changed it after publishing ended up
  with two Galaxy entries for one role, and this avoids repeating that.

- RESTORED: `devel_pipeline_validation.yml` and `main_pipeline_validation.yml`. They were removed
  earlier in this cycle on the assumption the Azure/OpenTofu pipeline was dormant; it is not. The
  pipeline provisions a Windows host with OpenTofu, runs the role against it and destroys the host
  again, and it is the only thing in this repo that exercises the role on a real target. It caught a
  defect no static check could: `WN11-CC-000052` reconfigured the Schannel ECC curve list and broke
  the WinRM TLS handshake on the following task, leaving the host unreachable mid-run.
- CHANGED: `actions/checkout` in both pipeline workflows is pinned to `v7` rather than `v4`, matching
  the Windows Fleet. `first-interaction` stays at `v3.1.0`.

- FIXED: **Tofu Destroy did not run when `ENABLE_DEBUG` was unset.** The teardown step in both
  pipeline workflows was gated on `env.ENABLE_DEBUG == 'false'`, which is false for an unset or
  empty variable, so the Azure test instance was left running after the job. Now gated on
  `!= 'true'`, which tears down by default and keeps the instance only when debugging is explicitly
  requested. This role is the only one in the Windows STIG line that kept its pipeline workflows
  through this cycle, so it is the one where the leak was live.
- FIXED: **the IAC_BRANCH test was a shell syntax error when the variable was unset.**
  `if [ ${{ vars.IAC_BRANCH }} != '' ]` expands to `if [ != '' ]` with no value. Replaced with
  `if [ -n "${{ vars.IAC_BRANCH }}" ]` in both pipeline workflows.
- FIXED: **the debug step echoed an undefined variable.** `$benchmark_type` is never set; the
  environment carries `TF_VAR_benchmark_type`. Corrected, so `DEBUG - Show IaC files` reports the
  benchmark type instead of an empty string.
- ADDED: explicit least-privilege `permissions:` blocks on the pipeline jobs, rather than inheriting
  the default token scope, and `workflow_dispatch` so either pipeline can be run manually. Both were
  already carried elsewhere in the Windows Fleet and are adopted here for parity.

- CHANGED: `repo_qa.yml` now runs on the self-hosted runner rather than a hosted one. The
  linter install is isolated in a virtualenv, which a hosted runner would not need: this
  runner persists between jobs, so installing into its interpreter would leak the pinned
  `yamllint` and `ansible-lint` versions into every other workflow sharing it, and a bare
  `pip install` into a system interpreter is refused on current Debian and Ubuntu
  (externally-managed-environment). The venv is prepended to `PATH` so the checker's
  `shutil.which` lookup still finds both linters.
- CHANGED: `repo_qa.yml` runs on pull requests only. The `push` trigger on `main`/`latest` and
  the weekly `schedule` cron are removed: a push to a release branch arrives through a pull
  request anyway, and the cron reported drift on a build nobody was watching.
  `workflow_dispatch` is retained for checking drift deliberately.

- FIXED: the `repo_qa.yml` comment describing `.qa_baseline.json` claimed one absorbed finding,
  `benchmark_version` reported unused. The baseline is empty: `benchmark_version` is now read by
  `templates/compliance_facts.ps1.j2`, so the unused-variable check no longer fires on it. The
  comment now matches the file.

- FIXED: `repo_qa.yml` pinned the QA checker at `2.8.3`, which resolves a role's defaults as the
  single file `defaults/main.yml` and aborts before running any check when it is absent. This
  role now keeps its defaults in a `defaults/main/` directory, so the pinned checker could not
  run against it at all and the gate would have failed on its first pull request. Pinned to
  `2.8.4`, which accepts the directory and also understands the `Cat<N>` task directories and
  the Windows toggle shape.
- CHANGED: the checker run now names the variable prefix with `-b`. Left to auto-detect it
  misidentifies this role's benchmark type, reports Rule Coverage as a green PASS having compared
  nothing, and keys Unused Variables on whichever prefix it guessed. `.qa_baseline.json` is
  regenerated with the same flag so the two stay in step.

- CHANGED: `repo_qa.yml` no longer depends on `actions/setup-python` succeeding. It prefers the
  runner's own `python3` when that is 3.10 or newer, falls back to `actions/setup-python` only
  when it is not, and then asserts the floor before installing anything, so a runner without a
  suitable interpreter fails with a message naming the version it found rather than with a pip
  resolution error several steps later. 3.10 is the real floor: `yamllint` and `ansible-lint`
  both declare `requires-python >= 3.10`, while the checker itself is standard library only and
  runs on 3.8. Nothing is installed system-wide and no `sudo` is needed on either path, which
  matters on a runner shared with other workflows.

- FIXED: the QA gate reported `Rule Coverage` as SKIP, having compared nothing. This role uses
  two variable prefixes - `win11stig_*` for tunables and `wn11_<family>_<id>` for rule toggles -
  and the checker keys every check off one of them, so no single invocation is honest. Naming
  `-b win11stig` lets Unused Variables see the tunables, but supplying `-b` at all bypasses the
  shared detector for one that cannot return `stig_win`, so Rule
  Coverage found no toggles. Letting it auto-detect fixes Rule Coverage but leaves Unused
  Variables blind to an undefined `win11stig_*` tunable, which is the class that hid an undefined
  variable in this fleet's firewall remediation. The gate now runs both ways and requires both
  to pass. The root cause is in the checker: `_detect_benchmark_type` cannot return `stig_win`.

### Remediation defects fixed - Windows Fleet parity sweep

Found while auditing the Windows Fleet; every one of these was present here too.

- FIXED: `WN11-00-000130` referenced a bare `filtered_certificate_files` at its alert task, a name
  defined nowhere and carrying no `default()`, so the task raised an undefined-variable error when
  reached. The set_fact above it defines `discovered_00_000130_filtered_certificate_files`.
- FIXED: four `AUDIT`-labelled tasks performed writes. `--tags audit` is a real selection
  mechanism, so they handed ACL changes and registry writes to an operator who asked for a
  read-only pass. `WN11-00-000105` took ownership of `C:\Windows\System32\snmp.exe` and granted
  Administrators full control while declaring `changed_when: false`, so it mutated a system binary
  and reported `ok`; it is now `PATCH` with `changed_when: true`. `WN11-AU-000083` and
  `WN11-AU-000107` ran `AuditPol /set` and are now `PATCH`, matching their own structural twins.
- FIXED: `WN11-AU-000585` also wrote `ProcessCreationIncludeCmdLine_Enabled`, which is
  `WN11-CC-000066`'s value and is already applied independently by that control. The duplicate
  write, filed under the wrong control and under an `AUDIT` label, is removed; `WN11-AU-000585`
  keeps only the `AuditPol` work its own check text asks for.
- FIXED: nine facts were read through the injected top-level names. `INJECT_FACTS_AS_VARS`
  defaulting to true is deprecated and the behaviour is removed in ansible-core 2.24, at which
  point those names become undefined. All nine now read `ansible_facts['...']`. `ansible_version`
  and `ansible_run_tags` are deliberately untouched: they are magic variables, not facts.


- `README.md`: corrected the Followers badge label casing to match the other four roles. This role's
  `CONTRIBUTING.md`, heading text and social badge were already current and are unchanged
- `defaults/main.yml` moved to `defaults/main/main.yml`, matching the directory layout the Linux
  roles have adopted. Ansible loads role defaults from the directory, so no task or template change
  was needed and no variable name or value changed. Verified by loading the defaults tree through
  Ansible's role-defaults loader
- CHANGED: `benchmark_version` is now expressed numerically, `v2r9` becomes `v2.9.0`. This is the
  value `templates/compliance_facts.json.j2` renders into the local fact `Benchmark_release`, so that
  fact changes from `STIG-v2r9` to `STIG-v2.9.0` on the next run
- the benchmark content is unchanged and remains V2R9

## Based on STIG v2.9.0 - 2026 August - Contributing guide and README refresh

- replaced `CONTRIBUTING.rst` with `CONTRIBUTING.md`, carrying the current Ansible-Lockdown
  contributing guide. It adds the approved-contributor model for pull requests, keeps issues open to
  everyone, and retains the DCO 1.1 text and the GPG plus Signed-off-by requirements
- `README.md`: added a Contributing section pointing at `CONTRIBUTING.md`, and refreshed the
  Community Contribution section, which still described the previous open pull request workflow and
  so contradicted the new guide
- `README.md`: removed the decorative emoji from headings, and switched the social badge from
  `twitter.com` to `x.com`

## Based on STIG v2.9.0 - Release 2.9.0 - August 2026

Update to STIG Version 2 Release 9

  - FIXED: the non-cloud account lockout path applied WN11-AC-000015 (`ResetLockoutCount`) before
    WN11-AC-000005 (`LockoutDuration`). secedit rejects a reset counter greater than the current
    duration, so on a host still at the Windows default duration of 10 the control failed with
    "Failed to import secedit.ini file ... The parameter is incorrect". Both values default to
    15, so this hit any host that had not already been raised to 15 or above. The order is now
    BadCount -> Duration -> Reset on both paths, matching the cloud path which was already
    correct.
  - BREAKING: `win11stig_cat1_patch`, `win11stig_cat2_patch` and `win11stig_cat3_patch` are renamed
    to `win11stig_cat1_controls`, `win11stig_cat2_controls` and `win11stig_cat3_controls`,
    matching the Windows Fleet and the names the tasks read. Rename them if you override
    them; the old names are no longer read.
  - CHANGED: the audit probes that tolerate a non-zero return code now use `failed_when: false`
    instead of `ignore_errors: true`, matching the rest of the fleet. `findstr` exits 1 when it
    finds no match, which is a normal audit result, so those probes were reporting a red task
    failure for a condition the control is designed to detect.
  - CHANGED: `defaults/main.yml` reordered to the fleet layout - benchmark metadata, then the
    OS and facts switches, then the CAT toggles. The comment claiming `benchmark_version` is
    read only by the QA tooling was wrong; the compliance facts template renders it.
  - ADDED: `skip_os_check`, defaulting to false. Setting it true bypasses the OS version and
    family assert for hosts the check misidentifies.
  - ADDED: `create_benchmark_facts` and `ansible_facts_path`. The role now writes
    `compliance_facts.ps1` under `C:\ProgramData\ansible\facts.d`, recording the benchmark
    release, the run date and which CAT levels were enabled. Windows has no default local-facts
    directory, so it is collected only when `ansible.windows.setup` is given a matching
    `fact_path`; it then surfaces as `ansible_compliance_facts`.
  - ADDED: `company_title` and `file_managed_by_ansible` in `vars/main.yml`, the provenance
    strings the rest of the fleet uses to head managed files.
  - BREAKING: `win11stig_min_ansible_version` is renamed to `min_ansible_version` and moved from
    `defaults/main.yml` to `vars/main.yml`, matching the rest of the fleet. Rename it if you
    override it; the old name is no longer read.
  - FIXED: every operational switch used in a `when:` or a template is now filtered through
    `| bool`. Supplied as an extra var (`-e skip_reboot=false`) a switch arrives as the string
    "false", which is truthy, so a negated conditional evaluated to the opposite of what was
    asked and a non-negated one failed outright on ansible-core 2.19+.
  - CHANGED: `ChangeLog.md` renamed to `CHANGELOG.md` to match the rest of the fleet.
  - Coverage is now exact against V2R9: 257 of 257 rules, nothing missing and nothing extra
  - Added WN11-00-000126, WN11-00-000400, WN11-AU-000583, WN11-AU-000586, WN11-AU-000587,
    WN11-AU-000588 and WN11-AU-000589
  - Removed the eight controls V2R9 withdrew: WN11-00-000025, WN11-00-000145, WN11-00-000220,
    WN11-00-000250, WN11-AU-000550, WN11-CC-000065, WN11-CC-000197 and WN11-SO-000005
  - Corrected 51 SV-IDs, 16 CCI sets and two SRG identifiers against the benchmark, and every
    control title now matches the V2R9 wording
  - Titles follow V2R9 in naming the department DoW; certificate subject names remain DoD because
    the check text still matches on them

Controls that were not being applied

  - WN11-AC-000005, WN11-AC-000010 and WN11-AC-000015 were skipped on every host that is not a
    cloud instance, because the inline tasks and the cloud-ordered import were both gated on the
    same condition instead of opposite ones
  - WN11-CC-000075 (CAT 1) and WN11-00-000010 were restricted to domain-joined systems, which the
    benchmark does not require
  - WN11-CC-000255 was gated on a fact that could never be true, so it applied nowhere. Its gate
    now follows the check text, which exempts only virtual desktops refreshed on logoff
  - WN11-CC-000252 wrote AllowGameDVR under a different registry key from the one the check reads

Fixes

  - Cloud detection now identifies an instance by system vendor. The previous condition matched
    every host that was not VMware, including bare metal
  - The OS gate no longer fails with a template error on a non-administrative connection, and it
    distinguishes Windows 11 from Windows Server 2025, which shares build 10.0.26100
  - The VDI persistence detection referenced a register the role never created, so no system could
    be identified as a persistent VDI
  - default('') and default([]) now pass their second argument at 16 sites, so a null value is
    caught rather than reaching `in`, `length` or `trim`
  - Removed four prelim and main tasks whose registers no task read
  - WN11-AU-000505 defaulted the security event log below the size V2R9 requires

Structure and tooling

  - Control tasks are now organised as tasks/Cat1, Cat2 and Cat3, one file per control family,
    matching the Windows Fleet. Execution order within each family is unchanged
  - Every register and set_fact now uses the discovered_ prefix, matching the Windows Fleet.
    wn11_ is reserved for the rule toggles alone, so wn11_au_000583 the toggle and
    discovered_au_000583_audit the register are no longer easy to confuse. Registers are internal to
    the role, so this changes nothing for anyone setting variables
  - .ansible-lint no longer carries the parseable key, which current ansible-lint rejects outright,
    so the role could not be linted at all
  - Added a Repo QA gate, .qa_config.yml and a one-entry baseline
  - Pinned the collection requirements and dropped community.general, which no task calls
  - Pipeline workflows now trigger on benchmark branches, pin actions/first-interaction, and
    restrict the credential-bearing job to pull requests from this repository
  - Removed update_galaxy.yml, which targeted a branch this repository does not have
  - .gitignore no longer ignores .github/ wholesale, which silently swallowed new workflow files

  - CHANGED: single-entry `when:` and `tags:` are now written inline rather than as one-item
    lists, matching the fleet. 40 occurrences across `tasks/` and `handlers/`, 60 percent of them
    in `prelim.yml` and `main.yml`. Verified cosmetic by parsing every touched file before and
    after, normalizing any one-element `when`/`tags`/`notify` list to its scalar, and asserting the
    resulting task structures are identical. Four `when:` conditions are long or-chains that would
    be unreadable on one line; those use a `>-` folded scalar so the condition stays a scalar rather
    than a one-item list, matching the idiom already used in `tasks/main.yml` of the Windows Fleet
    role.
  - CHANGED: sibling tasks in `tasks/Cat1/WN11-CC-xxxxxx.yml` are separated by a blank line. Five
    tasks ran directly into the next `- name:`. Tasks preceded by their own comment were left
    alone, since the comment belongs to the task below it.
  - FIXED: the `WN11-AC-000010` comment in `defaults/main.yml` named `win11stig_lockout_bad_count`,
    which is not a variable this role declares. The setting it documents is
    `win11stig_bad_login_lockout_count`, declared four lines below it. Comment only; no task read
    the wrong name.
  - CHANGED: the README is now plain ASCII. Emoji removed from the headings, the unicode arrows in
    the NIST reference table converted to ASCII, and "a auditing tool" corrected to "an auditing
    tool".

Note for anyone overriding variables

  - The eight rule toggles listed above are gone. Setting them now has no effect; nothing errors
  - win11stig_security_max_log_file_size now defaults to 5120000, raised from 1024000
  - win11stig_min_ansible_version is now 2.16.1
  - No consumer-facing variable was renamed in this release

## Based on STIG v2.3.0 - Release 1.3.0 - April 2025

General Updates
  - Update Release for V2R3 STIG
  - Updated Tagging
  - Rule IDs Updated For Changes

## Based on STIG v2.2.0 - Release 1.0.0 - March 2025

General Updates
  - First Release for V2R2 STIG
  - Removed state: present from all win_regedit modules.
  - Added NIST Tagging
  - Added Workflows
