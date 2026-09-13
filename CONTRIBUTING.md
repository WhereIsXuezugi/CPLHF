# Contributing

This project started as a personal CyberPatriot toolkit and is shared as a
reference implementation, so contributions are welcome but held to a
higher bar than "it worked on my machine."

## Ground rules

1. **Every module stays idempotent.** Re-running `bin/harden.sh` against
   an already-hardened system must not error out or duplicate
   configuration blocks. Use `ensure_line_in_file` / `ensure_block_in_file`
   from `lib/common.sh` instead of raw `echo >>`.
2. **Every destructive action goes through `run` or an explicit
   confirmation.** No module should delete, purge, or overwrite files
   without either the `run` wrapper (which respects `--dry-run`) or a
   typed confirmation for irreversible actions (see
   `filesystem_remove_media_files` for the pattern).
3. **Cite your source.** If you add a new hardening step, add a matching
   entry to `docs/security-controls.md` referencing the CIS Benchmark
   section, NIST 800-53 control, or other public standard it implements.
   "Seemed like a good idea" is not sufficient justification for a change
   that affects a running system.
4. **Lint before you push.** Run `shellcheck` against any file you touch:

   ```
   shellcheck lib/*.sh bin/*.sh tools/*.sh
   ```

5. **Test in a VM.** These scripts modify SSH access, firewall rules, and
   PAM configuration. Test in a disposable virtual machine, not your
   daily-driver system.

## Reporting issues

Open an issue describing the Ubuntu/Mint version, the module involved,
and whether `--dry-run` reproduces the problem. Log excerpts from
`~/hardening-run/harden.log` are more useful than a description of the
symptom alone.
