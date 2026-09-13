#!/usr/bin/env sh
# tools/list-nonstandard-users.sh
#
# Lists every account with a UID >= 1000 (Ubuntu/Debian's convention for
# regular, human-created accounts) that is not on a supplied allow-list,
# and prints a count. Meant to be run right after imaging a competition
# machine to spot accounts that were pre-planted as part of the exercise's
# injected vulnerabilities.
#
# Usage:
#   ./tools/list-nonstandard-users.sh alice bob
#
#   (lists every UID >= 1000 account that is not "alice" or "bob")

set -eu

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 EXPECTED_USER [EXPECTED_USER ...]" >&2
    echo "Lists UID >= 1000 accounts in /etc/passwd that are not in the expected list." >&2
    exit 1
fi

allow_list=$(printf '%s ' "$@")

awk -F':' -v allow=" $allow_list" '
    $3 >= 1000 {
        needle = " " $1 " "
        if (index(allow, needle) == 0) {
            print "unexpected user: " $1 " (uid " $3 ")"
            count++
        }
    }
    END { print "total unexpected accounts: " count + 0 }
' /etc/passwd
