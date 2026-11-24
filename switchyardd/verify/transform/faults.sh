#!/bin/sh
# Shows that the checks in this folder can still fail. See VERIFY.md, "Faults that must break a check".
#
# For each patch in faults/ it makes a scratch copy of switchyardd/src/transform.rs and of this crate,
# applies the patch there, and requires the generated-input tests and the Kani harness listed below to
# fail on the rule that the patch breaks. Then it does the opposite for the finding: its test and its
# harness must fail on the code as it is, and pass with the patch in fixes/.
#
# usage: sh switchyardd/verify/transform/faults.sh [--no-kani]
# The working tree is never patched. With Kani the run takes about a minute and a half; --no-kani skips the
# harnesses, for a machine without cargo-kani, and then shows only that the tests can fail.
set -eu
cd "$(dirname "$0")"
here=$PWD
kani=1
[ "${1:-}" != --no-kani ] || kani=
copy=$(mktemp -d)
trap 'rm -rf "$copy"' EXIT
crate=$copy/switchyardd/verify/transform
out=$copy/out
fail() { echo "FAIL: $*" >&2; exit 1; }

# A new copy for each patch, without target: with a shared target cargo can run a stale binary.
fresh() {
  rm -rf "$copy/switchyardd"
  mkdir -p "$copy/switchyardd/src" "$crate"
  cp "$here/../../src/transform.rs" "$copy/switchyardd/src/"
  cp -R Cargo.toml Cargo.lock src tests "$crate/"
  if [ -z "${1:-}" ]; then return 0; fi
  (cd "$copy" && git apply "$here/$1") || fail "$1 does not apply: the covered code changed, so make the patch again"
  ! cmp -s "$here/../../src/transform.rs" "$copy/switchyardd/src/transform.rs" || fail "$1 changed nothing"
}

# Extra cargo options for both functions below: empty, or the feature that holds the finding.
opts=

# tests_fail PATCH TEST...: the run of the generated tests must fail, and on each named test.
tests_fail() {
  patch=$1; shift
  # shellcheck disable=SC2086
  if (cd "$crate" && cargo test -j2 $opts --test generated > "$out" 2>&1); then
    fail "$patch: the generated tests pass"
  fi
  for t in "$@"; do
    grep -q "^test $t ... FAILED" "$out" || { cat "$out"; fail "$patch: test $t did not fail"; }
  done
}

# harness_fails PATCH HARNESS TEXT: the harness must fail, and its output must name the failed check by TEXT.
harness_fails() {
  [ -n "$kani" ] || return 0
  # shellcheck disable=SC2086
  if (cd "$crate" && cargo kani -Z stubbing -j2 --output-format=terse $opts --harness "$2" > "$out" 2>&1); then
    fail "$1: harness $2 passes"
  fi
  grep -qF "$3" "$out" || { cat "$out"; fail "$1: $2 failed, but not on: $3"; }
}

payload='Failed Checks: "render returned more bytes than max_payload"'
body='Failed Checks: "truncate_body returned more chars than max_chars"'
# Kani cannot print the message of this panic, so the check is named by the std function that panics.
slice='SliceIndex<str> for std::ops::RangeTo<usize>>::index'

fresh faults/render_marker_budget_off_by_one.patch
tests_fail render_marker_budget_off_by_one render_every_small_string_tag_and_limit long_generated_inputs
harness_fails render_marker_budget_off_by_one render_4_bytes_any_limit "$payload"
# The same break must also fail a harness that takes the Some(tag) arm.
harness_fails render_marker_budget_off_by_one render_tag_1_body_2_any_limit "$payload"
echo "ok: render_marker_budget_off_by_one breaks payload-limit"

fresh faults/render_small_limit_rounds_up.patch
tests_fail render_small_limit_rounds_up render_every_small_string_tag_and_limit long_generated_inputs
harness_fails render_small_limit_rounds_up render_2_bytes_any_limit "$payload"
echo "ok: render_small_limit_rounds_up breaks payload-limit"

fresh faults/truncate_body_no_room_for_marker.patch
tests_fail truncate_body_no_room_for_marker truncate_body_every_small_string_and_limit long_generated_inputs
harness_fails truncate_body_no_room_for_marker truncate_body_2_bytes_limit_1 "$body"
echo "ok: truncate_body_no_room_for_marker breaks body-limit"

fits='Failed Checks: "truncate_body changed a body that fits in max_chars"'
fresh faults/truncate_body_marks_what_fits.patch
tests_fail truncate_body_marks_what_fits truncate_body_every_small_string_and_limit long_generated_inputs
harness_fails truncate_body_marks_what_fits truncate_body_2_bytes_limit_2_up "$fits"
echo "ok: truncate_body_marks_what_fits breaks body-limit"

fresh faults/render_cut_ignores_char_boundary.patch
tests_fail render_cut_ignores_char_boundary render_every_small_string_tag_and_limit long_generated_inputs
grep -q 'is not a char boundary' "$out" || { cat "$out"; fail "render_cut_ignores_char_boundary: the tests failed, but not on a panic"; }
harness_fails render_cut_ignores_char_boundary render_5_bytes_any_limit "$slice"
echo "ok: render_cut_ignores_char_boundary breaks no-panic"

# The finding: body-limit breaks at max_chars 0 on the code as it is, and holds with the fix.
zero='Failed Checks: "truncate_body returned a char although max_chars is 0"'
opts='--features findings'
fresh
tests_fail "the code as it is" finding_truncate_body_limit_zero
harness_fails "the code as it is" finding_truncate_body_limit_zero "$zero"
fresh fixes/truncate_body_zero_limit_returns_nothing.patch
(cd "$crate" && cargo test -j2 --features findings --test generated > "$out" 2>&1) \
  || { cat "$out"; fail "the fix does not make the generated tests and the finding test pass"; }
grep -q '^test result: ok. 4 passed' "$out" || { cat "$out"; fail "with the fix, 4 tests must pass"; }
if [ -n "$kani" ]; then
  (cd "$crate" && cargo kani -Z stubbing -j2 --output-format=terse --features findings \
    --harness finding_truncate_body_limit_zero --harness truncate_body_2_bytes_limit_1 > "$out" 2>&1) \
    || { cat "$out"; fail "the fix does not make the finding harness pass"; }
  grep -q 'Complete - 2 successfully verified harnesses, 0 failures, 2 total' "$out" \
    || { cat "$out"; fail "with the fix, 2 harnesses must pass"; }
fi
echo "ok: the finding fails on the code as it is, and passes with fixes/truncate_body_zero_limit_returns_nothing.patch"
[ -n "$kani" ] || echo "note: --no-kani, so only the generated tests were shown to fail"
