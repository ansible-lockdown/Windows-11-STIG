# Windows 11 DISA STIG

## Configure a Windows 11 Enterprise system to be [DISA STIG](https://public.cyber.mil/stigs/downloads/) compliant.

### Based on [Windows DISA STIG Version 2, Rel 9 released on August 10th, 2026](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R9_STIG.zip)

---

![Org Stars](https://img.shields.io/github/stars/ansible-lockdown?label=Org%20Stars&style=social)
![Stars](https://img.shields.io/github/stars/ansible-lockdown/Windows-11-STIG?label=Repo%20Stars&style=social)
![Forks](https://img.shields.io/github/forks/ansible-lockdown/Windows-11-STIG?style=social)
![Followers](https://img.shields.io/github/followers/ansible-lockdown?style=social)
[![X URL](https://img.shields.io/twitter/url/https/x.com/AnsibleLockdown.svg?style=social&label=Follow%20%40AnsibleLockdown)](https://x.com/AnsibleLockdown)

![Discord Badge](https://img.shields.io/discord/925818806838919229?logo=discord)

![Release Branch](https://img.shields.io/badge/Release%20Branch-Main-brightgreen)
![Release Tag](https://img.shields.io/github/v/tag/ansible-lockdown/Windows-11-STIG?label=Release%20Tag&color=success)
![Main Release Date](https://img.shields.io/github/release-date/ansible-lockdown/Windows-11-STIG?label=Release%20Date)

![Devel Commits](https://img.shields.io/github/commit-activity/m/ansible-lockdown/Windows-11-STIG/devel?color=dark%20green&label=Devel%20Branch%20Commits)

![Issues Open](https://img.shields.io/github/issues-raw/ansible-lockdown/Windows-11-STIG?label=Open%20Issues)
![Issues Closed](https://img.shields.io/github/issues-closed-raw/ansible-lockdown/Windows-11-STIG?label=Closed%20Issues&color=success)
![Pull Requests](https://img.shields.io/github/issues-pr/ansible-lockdown/Windows-11-STIG?label=Pull%20Requests)

![License](https://img.shields.io/github/license/ansible-lockdown/Windows-11-STIG?label=License)

---

## Looking For Support?

[Lockdown Enterprise](https://www.lockdownenterprise.com#GH_AL_WINDOWS_11_stig)

[Ansible Support](https://www.mindpointgroup.com/cybersecurity-products/ansible-counselor#GH_AL_WINDOWS_11_stig)

### Community

Join us on our [Discord Server](https://www.lockdownenterprise.com/discord) to ask questions, discuss features, or just chat with other Ansible-Lockdown users.

### Contributing

Bug reports and feature requests are welcome from everyone, please raise an issue.

Pull requests are accepted from approved contributors only. To be onboarded, join the [Discord Server](https://www.lockdownenterprise.com/discord) and request contributor access. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

---

## Caution(s)

This role **will make changes to the system** which may have unintended consequences. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

Check Mode is not supported! The role will complete in check mode without errors, but it is not supported and should be used with caution.

This role was developed against a clean install of Windows 11. If you are implementing to an existing system please review this role for any site specific changes that are needed.

To use release version please point to main branch and relevant release for the STIG benchmark you wish to work with.

---

## Domain Members

Account policy is domain scoped. On a domain joined host the Default Domain Policy owns
`[System Access]`, so the 13 secedit backed controls in this role cannot hold there. `prelim.yml`
detects domain membership, skips those controls and warns once, rather than writing settings the
domain will not keep.

Measured on a Windows 11 Pro workstation joined to a Server 2025 domain:

| Setting | STIG target | On the domain member |
|---|---|---|
| `MinimumPasswordLength` | 14 | **7** |
| `MaximumPasswordAge` | 60 | **42** |
| `LockoutBadCount` | 3 | **0** |
| `PasswordHistorySize` | 24 | 24 |
| `MinimumPasswordAge` | 1 | 1 |

The first three are the Default Domain Policy's own values and do not meet the STIG. After a
complete hardening run, all 11 `[System Access]` values were byte-identical to the pre-run
baseline, because the guard skipped those controls rather than writing settings that would not
survive. That run raised 23 warnings, including `Account policy is domain scoped`.

Set these in the Default Domain Policy instead. Everything outside `[System Access]` applies
normally on a domain member.

---

## Standalone Members

On a workgroup host `prelim.yml` does not set the domain scoped fact, so the `[System Access]`
controls skipped on a domain member are in scope here and the role drives them.

Measured on a standalone Windows 11 Pro workstation, reboot inclusive:

| | Baseline | Remediated |
|---|---:|---:|
| pass | 87 (33.9%) | 208 (80.9%) |
| fail | 145 (56.4%) | 24 (9.3%) |
| not applicable | 15 (5.8%) | 15 (5.8%) |
| CAT I open | 13 | 4 |

Ten more rules report not applicable than on a domain member, because the benchmark's
domain joined rules fall out of scope.

**In scope does not mean applied by default.** Of the account policy controls the domain guard
releases here, only `WN11-AC-000035` applies on a default run. The rest carry a second guard, and
each one is an operator decision rather than an oversight:

| Control | Second guard | Why |
|---|---|---|
| `WN11-AC-000005`, `WN11-AC-000010`, `WN11-AC-000015` | `not win_skip_for_test` | account lockout can lock out the account the run is connected as |
| `WN11-SO-000020`, `WN11-SO-000025` | `win11stig_admin_username` / `win11stig_guest_username` still at their placeholder | the role will not invent a name for the built in accounts, and warns instead |
| `WN11-00-000090` | `win11stig_password_expires` | forcing expiry on every local account is a site decision |

To apply them, set `win_skip_for_test: false` once you have console access or a break glass path,
replace both placeholder usernames, and set `win11stig_password_expires: true`.

A standalone host is less forgiving than a domain member. `WN11-CC-000037` and `WN11-UR-000070`
remove network logon for local accounts, and on a workgroup machine every account is local, so
there is no domain principal to fall back on. Applying either leaves console access only.

## Matching A Security Level For STIG

It is possible to only run controls that are based on a particular security level for STIG.
This is managed using tags:

- CAT1
- CAT2
- CAT3

The controls found in defaults/main also need to reflect those control numbers due to aligning every control to the audit component.

## Coming From A Previous Release

STIG releases always contain changes, it is highly recommended to review the new references and available variables. This has changed significantly since the initial release of ansible-lockdown.
This is now compatible with python3 if it is found to be the default interpreter. This does come with pre-requisites which it configures the system accordingly.

Further details can be seen in the [Changelog](./CHANGELOG.md)

## Auditing

This role remediates. To measure whether a host actually passes the benchmark, the role can scan
it with [SCAP Compliance Checker](https://www.niwcatlantic.navy.mil/scap/) (SCC), the scanner DISA
authors and validates its SCAP content against.

The audit is part of the role rather than a separate playbook, and is off by default:

| Variable | Purpose |
|---|---|
| `setup_audit` | stage SCC on the target |
| `run_audit` | scan before and after remediation |
| `audit_only` | scan and stop, applying nothing |
| `fetch_audit_output` | collect the result sets |

A measured hardening run:

```bash
ansible-playbook -i <inventory> site.yml \
  -e setup_audit=true -e run_audit=true -e fetch_audit_output=true
```

Scan without changing anything:

```bash
ansible-playbook -i <inventory> site.yml -e audit_only=true -e setup_audit=true
```

Both scans run because the delta is the evidence. A post-remediation score on its own cannot tell
you whether the role fixed findings or whether the image was already compliant, so scan a host that
has not been hardened before, or roll back to a clean snapshot first.

Each scan writes a summary and SCC's result set to `audit_log_dir` on the node, and
`fetch_audit_output` collects them to `audit_output_destination`. The scanner is removed when the
run finishes; the result sets are not, so they accumulate on the scanned host and need pruning on
your own schedule. By default that set is the All
Settings HTML report and the DISA CKL checklist; `scc_report_options_override` changes which
reports SCC writes.
Findings are keyed by STIG control ID (`WN11-CC-000075`), the same identifiers this role uses for
its task names and tags, so a finding maps straight to the task that addresses it.

Results differ between domain-joined and standalone hosts and the two are not comparable. See
[docs/README_SCC_QuickStart.md](docs/README_SCC_QuickStart.md) for that, for the profile choice,
for the manual-check handling, and for what the result files contain before you publish them.

## Compliance facts

With `create_benchmark_facts` enabled (the default), the role writes a record of what it applied to:

```
C:\ProgramData\ansible\facts.d\compliance_facts.json
```

It captures the benchmark release, the run date and which CAT levels were enabled.

Windows has no default local-facts directory, so unlike the Linux roles this file is **not**
collected automatically. Ask for it explicitly:

```yaml
- name: Read the compliance facts
  ansible.windows.setup:
    fact_path: 'C:\ProgramData\ansible\facts.d'
```

It then appears as `ansible_compliance_facts` - not under `ansible_local`, which is the Linux
convention. Set `ansible_facts_path` to relocate the directory, or `create_benchmark_facts: false`
to skip writing it.

## Documentation

- [Read The Docs](https://ansible-lockdown.readthedocs.io/en/latest/)
- [Getting Started](https://www.lockdownenterprise.com/docs/getting-started-with-lockdown#GH_AL_WINDOWS_11_stig)
- [Customizing Roles](https://www.lockdownenterprise.com/docs/customizing-lockdown-enterprise#GH_AL_WINDOWS_11_stig)
- [Per-Host Configuration](https://www.lockdownenterprise.com/docs/per-host-lockdown-enterprise-configuration#GH_AL_WINDOWS_11_stig)
- [Getting the Most Out of the Role](https://www.lockdownenterprise.com/docs/get-the-most-out-of-lockdown-enterprise#GH_AL_WINDOWS_11_stig)

## Requirements

**General:**

- Basic knowledge of Ansible, below are some links to the Ansible documentation to help get started if you are unfamiliar with Ansible

  - [Main Ansible documentation page](https://docs.ansible.com)
  - [Ansible Getting Started](https://docs.ansible.com/ansible/latest/user_guide/intro_getting_started.html)
  - [Tower User Guide](https://docs.ansible.com/ansible-tower/latest/html/userguide/index.html)
  - [Ansible Community Info](https://docs.ansible.com/ansible/latest/community/index.html)
- Functioning Ansible and/or Tower Installed, configured, and running. This includes all of the base Ansible/Tower configurations, needed packages installed, and infrastructure setup.
- Please read through the tasks in this role to gain an understanding of what each control is doing. Some of the tasks are disruptive and can have unintended consequences in a live production system. Also familiarize yourself with the variables in the defaults/main/main.yml file.

**Technical Dependencies:**

- Windows 11 - the role gates on the distribution caption and rejects Windows Server, including
  Server 2025, which shares build 10.0.26100 with Windows 11 24H2
- Running Ansible/Tower setup. This role requires ansible-core 2.16.1 or newer; the role asserts this at run time.
- Python3 Ansible run environment
- pywinrm

`pywinrm` is required on the controller host that executes Ansible; it is the connection library Ansible uses to reach a Windows target.

## Role Variables

### Breaking change in this release

Two security tunables still carried the legacy `wn11stig_` prefix. Role behaviour variables and
security tunables now all share the `win11stig_` prefix, matching the sibling Windows roles. If you
override either of these in inventory, group_vars or extra vars, rename them - the old names are no
longer read and your setting will be silently ignored.

- `wn11stig_internet_based_apps_to_check` becomes `win11stig_internet_based_apps_to_check`
- `wn11stig_pass_age_administrator` becomes `win11stig_pass_age_administrator`

Rule toggles are unchanged. They keep the `wn11_<control id>` form, for example
`wn11_au_000010`.


This role is designed so that the end user should not have to edit the tasks themselves. All customizing should be done via the defaults/main/main.yml file or with extra vars within the project, job, workflow, etc.

## Tags

There are many tags available for added control precision. Each control has its own set of tags noting what level, what OS element it relates to, whether it's a patch or audit, and the rule number. Additionally, NIST references follow a specific conversion format for consistency and clarity.

### Conversion Format for NIST References:

  1. Standard Prefix:

    - All references are prefixed with "NIST".

  2. Standard Types:

    - "800-53" references are formatted as NIST800-53.
    - "800-53A" references are formatted as NIST800-53A.
    - "800-53r4" references are formatted as NIST800-53R4 (with 'R' capitalized).

  3. Details:

    - Section and subsection numbers use periods (.) for numeric separators.
    - Parenthetical elements are separated by underscores (_), e.g., IA-5(1)(d) becomes IA-5_1_d.
    - Subsection letters (e.g., "b") are appended with an underscore.

### Example of Tag Usage:
Below is an example of the tag section from a control within this role. Using this example, if you set your run to skip all controls with the tag CCI-000018, this task will be skipped. Conversely, you can choose to run only controls tagged with CCI-000018.

```sh
tags:
      - WN11-AU-000040
      - CAT2
      - CCI-000018
      - CCI-000172
      - CCI-001403
      - CCI-001404
      - CCI-001405
      - CCI-002130
      - CCI-002234
      - SRG-OS-000004-GPOS-00004
      - SV-220752r958368_rule
      - V-220752
      - NIST800-53_AC-2_4
      - NIST800-53_AU-12_c
      - NIST800-53A_AC-2_4.1_i&ii
      - NIST800-53A_AC-12.1_iv
      - NIST800-53R4_AC-2_4
      - NIST800-53R4_AU-12_c
```
### Conversion Examples in Use:
  - NIST SP 800-53 :: AC-2 (4) -> NIST800-53_AC-2_4
  - NIST SP 800-53A :: AC-2 (4).1 (i&ii) -> NIST800-53A_AC-2_4.1_i&ii
  - NIST SP 800-53 Revision 4 :: AC-2 (4) -> NIST800-53R4_AC-2_4
  - NIST SP 800-53 :: AU-12 c -> NIST800-53_AU-12_c
  - NIST SP 800-53A :: AU-12.1 (iv) -> NIST800-53A_AC-12.1_iv
  - NIST SP 800-53 Revision 4 :: AU-12 c -> NIST800-53R4_AU-12_c

By maintaining this consistent tagging structure, it becomes easier to filter and manage tasks based on specific controls and compliance requirements.

## Community Contribution

Pull requests are accepted from approved contributors only, and issues are welcome from everyone.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the onboarding process, the rules, and the commit signing
requirements (GPG signature and Signed-off-by on every commit).

## Pipeline Testing

uses:

- ansible-core 2.16.1
- ansible collections - pulls in the latest version based on requirements file
- runs the role against a Windows target provisioned on Azure
- This is an automated test that occurs on pull requests into latest and benchmark branches
- self-hosted runners using OpenTofu

## Local Testing

- Ansible
  - ansible-core 2.16.1 or newer, with Python 3
- `pywinrm` on the controller, which is the connection library Ansible uses to reach a Windows target

## Credits and Thanks

Massive thanks to the fantastic community and all its members.

This includes a huge thanks and credit to the original authors and maintainers.
