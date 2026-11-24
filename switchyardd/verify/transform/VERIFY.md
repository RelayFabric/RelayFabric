# Verify the truncation limits of `transform.rs`

`switchyardd/src/transform.rs` holds the two places where the daemon shortens a message before a plugin sends it. `truncate_body` cuts the body to a route's `render.max_chars`, counted in chars. `render` cuts the assembled `"[tag]\nbody"` to the destination's payload cap, counted in bytes. This folder checks that neither returns more than its limit, and that neither panics.

Read this before you change `truncate_body` or `render`, or add a caller of either.

## Why this code

The closest tests are in `transform.rs` itself. `tiny_limits_never_exceed_budget` asserts `out.len() <= limit` for the limits 0 to 4, with one ASCII tag and one ASCII body. `truncates_on_char_boundary_with_marker` and `body_char_truncate_then_assemble_then_transport_byte_cap_both_apply` do the same for one string each, with 2-byte and 3-byte chars. The tests do not reach these cases:

- a limit under 3 that falls inside a multibyte char, such as `render(None, "é", Some(1))`: the loop that walks the cut back in that branch never runs in the tests;
- a 4-byte char anywhere, and an empty tag;
- `truncate_body` with `max_chars` 0 or 1.

## Does your change touch it?

| Code | What the checks take from it |
|------|------------------------------|
| `truncate_body`: `if body.chars().count() <= max_chars` | A body that fits is returned unchanged. |
| `truncate_body`: `let budget = max_chars.saturating_sub(1)`, `body.chars().take(budget).collect()`, `out.push('…')` | A longer body keeps its first `max_chars - 1` chars and gets one marker char. |
| `render`: `let full = match tag { ... }` | The string is assembled once. Nothing after the `match` reads `tag` or `body` again, so the limit depends only on `full` and `limit`. The Kani harnesses rely on that: most take the `None` arm, and four take the `Some(tag)` arm with small tags. |
| `render`: `let Some(limit) = max_payload else { return full; }` | With no limit there is no rule to keep. |
| `render`: `if full.len() <= limit` | A string that fits is returned unchanged. |
| `render`: the `if limit < 3` block | The cut starts at `limit` and only walks back, to a char boundary. No marker. |
| `render`: `let budget = limit - 3` to `format!("{}…", &full[..cut])` | The cut starts at `limit - 3` and only walks back. The marker `…` is 3 bytes. |
| `engine.rs`: `(r.render.max_chars > 0).then_some(r.render.max_chars)` | The only caller never calls `truncate_body` with `max_chars` 0. Rule `body-limit` assumes that. |
| `engine.rs`: `transform::truncate_body(&env.body, mc)` and `transform::render(render_tag, ...)` | These are the only callers. A new caller must keep the assumption above. |

```
covered:
  - switchyardd/src/transform.rs a02008348419
    > pub fn truncate_body(body: &str, max_chars: u32) -> String {
    > if body.chars().count() <= max_chars {
    > let budget = max_chars.saturating_sub(1);
    > body.chars().take(budget).collect();
    > out.push('…');
    > out
  - switchyardd/src/transform.rs 5cc32314b0c1
    > pub fn render(tag: Option<&str>, body: &str, max_payload: Option<usize>) -> String {
    > Some(t) => format!("[{t}]\n{body}"),
    > None => body.to_string(),
    > let Some(limit) = max_payload else {
    > if full.len() <= limit {
    > if limit < 3 {
    > while cut > 0 && !full.is_char_boundary(cut) {
    > return full[..cut].to_string();
    > let budget = limit - 3;
    > while cut > 0 && !full.is_char_boundary(cut) {
    > format!("{}…", &full[..cut])
  - switchyardd/src/engine.rs b4fa1135c4ff
    > let render_max_chars = route_cfg
    > .and_then(|r| (r.render.max_chars > 0).then_some(r.render.max_chars));
  - switchyardd/src/engine.rs e3f29bb6faec
    > let truncated_body = match render_max_chars {
    > Some(mc) => transform::truncate_body(&env.body, mc),
    > let body = transform::render(render_tag, &format!("{truncated_body}{notes}"), limit);
```

`drift.sh` compares the hash after each path with the text from the first cited line to the last. It is in the `maintain-formal-verification` skill of the `formal-proofs` plugin (https://github.com/jaschadub/skill-formal-proofs; this record was written with version 0.5.0). Run it from the repo root: `sh <that skill's folder>/drift.sh`. It cannot see a new caller of `truncate_body` or `render` in another file, so search for one: `grep -rn 'transform::\(truncate_body\|render\)' switchyardd/src`.

## The rules

| Rule | What it promises | Harm if it breaks |
|------|------------------|-------------------|
| `body-limit` | For every body and every `max_chars` of 1 or more, `truncate_body` returns at most `max_chars` chars. | A route sends a longer body than the `render.max_chars` that its operator set. |
| `payload-limit` | For every tag, every body, and every `max_payload` that is given, `render` returns at most `max_payload` bytes. | A plugin is handed a message that is larger than its protocol can carry, such as more than the 237 bytes of the Meshtastic and MeshCore transport classes. |
| `no-panic` | `truncate_body` and `render` return for every input: no panic, no overflow, no slice inside a char. | The delivery that is being rendered dies with the panic, and the message is not sent. |

`max_chars` counts chars and `max_payload` counts bytes. A body of `max_chars` chars can be up to four times as many bytes.

## Run the checks

Run both from `switchyardd/verify/transform`. This crate is not a member of the workspace, so `cargo test --workspace` does not run it. It compiles the real `switchyardd/src/transform.rs` by path.

1. **Bounded proof, on the real code.** `cargo kani -Z stubbing -j2 --output-format=terse`. It needs Kani 0.68.0: `cargo install --locked kani-verifier --version 0.68.0`, then `cargo kani setup`. A pass ends with `Complete - 27 successfully verified harnesses, 0 failures, 27 total.` It takes about two and a half minutes and up to 2.3 GB of memory for each of the two solver processes. A run that names fewer than 27 harnesses checked less. The output must also say `5 of 5 cover properties satisfied` once and `2 of 2 cover properties satisfied` ten times: those show that every branch of both functions was reached, so the pass is not an empty one. `-Z stubbing` is for the four harnesses with a tag; see "The stub" below.
2. **Generated inputs, on the real code.** `cargo test -j2 --test generated`. A pass is `test result: ok. 3 passed; 0 failed`. It takes two seconds. Each test fails by itself if a branch of the function never ran.

What a pass of check 1 means: [Kani](https://model-checking.github.io/kani/) covers every input up to the bound of each harness, and it also fails on any panic, overflow, or out-of-range access on those inputs.

- `truncate_body`: every valid UTF-8 body of 0 to 4 bytes, with every `max_chars` from 1 to `u32::MAX`.
- `render`: every valid UTF-8 string of 0 to 8 bytes as the assembled string (`tag` is `None`), with every `max_payload` from 0 to `usize::MAX`.
- `render` with a tag: every valid UTF-8 tag of 1 to 2 bytes, with every body of 2 to 3 bytes, with every `max_payload`.

What a pass of check 2 means: the rules held on the inputs that the tests generate, and no more. It is a test and not a proof.

- Every string of 0 to 9 chars over an alphabet with one char of each UTF-8 width (`a`, `é`, `あ`, `😀`), with every `max_chars` from 1 to 11.
- Every such string of 0 to 7 chars as the body, with no tag and with every tag of 0 to 2 such chars, with every `max_payload` from 0 to one more than the assembled length.
- 4,000 bodies of up to 2,500 chars drawn from all of Unicode with a fixed seed, with and without a tag of up to 40 chars, with limits at, next to, and far from the length.

**The stub.** The four harnesses with a tag replace one function of std, `Arguments::estimated_capacity`, by a function that returns 0. `format!` sizes its String with that function. Kani does not treat the value as a constant, and from the second piece of output on it explores formatters that the code never calls: without the stub, a 1-byte tag with a 2-byte body did not finish. The value is only a hint for the first allocation of the String, so a constant in its place changes no result of `render`. No other harness uses a stub.

A pass on a verification that no one updated says nothing about a change to the covered code. Run `drift.sh` first, and follow the steps below when it reports a change.

CI runs both checks and `faults.sh` on every push, in the job `kani` of `.github/workflows/ci.yml`, and `drift.sh` in the job `formal`. The `kani` job requires the 27 harnesses and the cover lines named in check 1, so a new harness or a new `kani::cover!` line must be counted there too.

## Why larger inputs behave the same

No tool checked this argument. The bounded proof stops at 4 and 8 bytes, and the tests stop at the inputs they generate.

- `truncate_body`: let `n` be the number of chars in the body and `m` be `max_chars`, at least 1. If `n <= m`, the body comes back unchanged, with `n <= m` chars. Otherwise `take(budget)` yields at most `budget = m - 1` chars however many follow, and `push` adds exactly one, so the result has at most `m` chars. No step depends on how long the body is.
- `render`: if `full.len() <= limit`, `full` comes back unchanged. If `limit < 3`, `cut` starts at `limit` and only decreases, so `full[..cut]` has at most `limit` bytes. Otherwise `limit >= 3`, so `limit - 3` cannot underflow, `cut` starts there and only decreases, and the result has `cut + 3 <= limit` bytes, because `…` is 3 bytes in UTF-8. Both loops stop, because `cut` reaches 0 at the latest and 0 is always a char boundary. `cut` is less than `full.len()`, so the slice is in range.

The argument trusts std for `chars().count()`, `take`, `collect`, `push`, `is_char_boundary`, and `format!`. `chars().count()` uses another algorithm for strings of 32 bytes or more. The proof never runs it; the test `long_generated_inputs` does.

A proof for every length needs a prover such as Verus or Creusot, and contracts written into `transform.rs` or a restated copy of it. That was not done, and it needs the owner's consent.

## When a change touches the covered code

These steps are for your own change, and for a change that you review before it lands. For a change that landed without them, follow the `maintain-formal-verification` skill of the `formal-proofs` plugin.

1. Read the change against the table above. If it alters nothing that the table describes, such as a rename or a comment, run both checks and go to step 6.
2. Update the verification from the code, before you run it. A new branch in `render` or `truncate_body` needs a `kani::cover!` line in `src/lib.rs` and a counter in `RenderRuns` in `tests/generated.rs`, so that a pass shows that it ran. If the code after the `match` in `render` starts to read `tag` or `body`, the argument that carries the harnesses without a tag over to a tag no longer holds, and Kani then covers a tag only at the sizes of the four tagged harnesses: say so under "What the checks do not cover". A new caller of `truncate_body` must not pass `max_chars` 0: cite its guard in the `covered:` block. When a change adds a step, a rule that names steps must name the new step too. That does not weaken the rule, as long as its plain sentence stays true.
3. Run both checks. Run check 2 first, because it is fast and it prints the input that fails.
4. If a check fails, replay it against the code before you change the check:
   - A test of check 2 prints the tag, the body, and the limit. Call the function with them and count the result. If it is over the limit, the change has a bug.
   - `Failed Checks: "render returned more bytes than max_payload"` or `"truncate_body returned more chars than max_chars"` from Kani is the same, found on a short string. To see the string, run that one harness again with `cargo kani -Z stubbing -Z concrete-playback --concrete-playback=print --harness proofs::<name> --exact`, without `-j2`. It prints the bytes of the string and then the limit. Without `--exact`, `--harness` runs every harness whose name holds that text.
   - `Failed Checks: This is a placeholder message` with a location inside std is a panic that the covered code caused, such as a slice inside a char. That breaks `no-panic`.
   - `unwinding assertion` is not a bug in the code. A loop now runs more often than the unwind number of that harness allows: raise the number in `harnesses!` in `src/lib.rs`.
   - `VERIFICATION:- FAILED` together with `0 of ... failed`, `Status: ERROR`, `Solver ran out of memory`, or `CBMC failed with status` is not a verdict. The solver gave up. Do not report it as a bug, and do not count it as a pass.
   - `Failed Checks: "truncate_body changed a body that fits in max_chars"` comes from the harnesses whose names end in `_up` or `_any_limit`. They ask for more than `body-limit`: a body with no more bytes than `max_chars` must come back unchanged. If check 2 passes on the same change, the limit holds and only that stronger statement broke. Then decide from the change whether it is intended.
   - A failure of `char_count_matches_std_4` or `_8` means that the counter of the harness is wrong, not the code.
5. Confirm that the checks can still fail: `sh switchyardd/verify/transform/faults.sh`, about a minute and a half. A pass prints six lines that start with `ok:`. A patch that no longer applies means that the covered code changed, so make it again from the new code.
6. Only then run `drift.sh --sync switchyardd/verify/transform/VERIFY.md` from the repo root, check that the line numbers it prints are the stretches that the `covered:` block means, and commit the record with the change.

When a change has a bug, the updated verification stays with that change, as a patch or on its branch, and no one syncs it. Do not weaken a rule, and do not narrow a harness, to make a check pass.

## Faults that must break a check

Each fault is a patch to `switchyardd/src/transform.rs`, made from the repo root. `faults.sh` applies each one to a scratch copy outside the repo, never to the working tree, and requires the listed checks to fail there. To try one by hand, copy `switchyardd/src/transform.rs` and this folder without `target` to the same relative paths in a scratch folder, run `git apply <patch>` at the top of that folder, and run the checks in the copy.

To make a patch again after the code changed: in a scratch folder, copy the changed `switchyardd/src/transform.rs` to `a/switchyardd/src/transform.rs` and to `b/switchyardd/src/transform.rs`, make the break from the table in the `b` copy, and save the output of `diff -u a/switchyardd/src/transform.rs b/switchyardd/src/transform.rs` over the old patch. `git diff` gives the same patch only after the change is committed. Before that, it also holds the change itself, and then the patch does not apply.

| Fault | The break in the code | Rule | What must fail |
|-------|-----------------------|------|----------------|
| `faults/render_marker_budget_off_by_one.patch` | `render` keeps `limit - 2` bytes before the 3-byte marker | `payload-limit` | Tests `render_every_small_string_tag_and_limit` and `long_generated_inputs`; harnesses `render_4_bytes_any_limit` and, with a tag, `render_tag_1_body_2_any_limit` |
| `faults/render_small_limit_rounds_up.patch` | under a limit of 3, `render` walks the cut forward to the next char boundary | `payload-limit` | The same two tests; harness `render_2_bytes_any_limit` |
| `faults/truncate_body_no_room_for_marker.patch` | `truncate_body` keeps `max_chars` chars and then adds the marker | `body-limit` | Tests `truncate_body_every_small_string_and_limit` and `long_generated_inputs`; harness `truncate_body_2_bytes_limit_1` |
| `faults/truncate_body_marks_what_fits.patch` | `truncate_body` adds the marker to a body that fits | `body-limit` | The same two tests; harness `truncate_body_2_bytes_limit_2_up` |
| `faults/render_cut_ignores_char_boundary.patch` | `render` cuts at `limit - 3` without walking back | `no-panic` | The two `render` tests, with `is not a char boundary`; harness `render_5_bytes_any_limit`, in `SliceIndex<str>` |

## Known weaknesses

One. The checks include it and show it to break.

- **`truncate_body` breaks `body-limit` when `max_chars` is 0.** `truncate_body("x", 0)` returns `"…"`: one char, where the limit allows none. `saturating_sub(1)` keeps 0 chars, and then the marker is added anyway. The doc comment of `truncate_body` says that callers treat 0 as "disabled" and do not call it, and the only caller, in `engine.rs`, keeps to that. So no message is affected today. The harm comes with a caller that passes 0 to mean "no limit": every body that is not empty is replaced by `…`, and its text is lost.
  - See it: `cargo test -j2 --features findings --test generated finding_truncate_body_limit_zero` fails with `truncate_body returned 1 chars for max_chars 0: body "x"`. `cargo kani -j2 --output-format=terse --features findings --harness finding_truncate_body_limit_zero` fails with `Failed Checks: "truncate_body returned a char although max_chars is 0"`.
  - The rule can be kept: with `fixes/truncate_body_zero_limit_returns_nothing.patch`, which returns an empty string for `max_chars` 0, both pass. `faults.sh` checks both directions. The patch shows that a fix exists. Which behavior is right for 0 is the owner's decision, and the product code is not changed here.

Both are behind the `findings` feature of this crate, so the two checks above pass without it.

## Code that no check runs

- The `Some(t) => format!("[{t}]\n{body}")` arm of `render` runs in check 1 only with a tag of 1 or 2 bytes and a body of 2 or 3 bytes, and only with the stub described under "Run the checks". Without the stub Kani 0.68.0 does not finish it: with a tag of 1 byte and a body of 2 bytes the solver ran out of 10 GB after 5 minutes. An empty tag never runs in check 1. Check 2 runs the arm with 21 tags for each small body, the empty tag among them, and for two long inputs in three.
- `return full` for `max_payload` `None` never runs in either check. There is no limit to keep.
- `attachment_notes` is not covered.

## What the checks do not cover

- **Sizes.** Check 1 stops at bodies of 4 bytes and assembled strings of 8 bytes. Check 2 is a test. For longer input there is the argument above, which no tool checked.
- **The tag under Kani.** See above. Past a tag of 2 bytes and a body of 3, and for an empty tag, check 1 covers a tag only through the argument that `render` reads nothing but `full` after it is assembled.
- **`max_chars` 0.** See "Known weaknesses".
- **Bytes of `truncate_body`.** It limits chars. Nothing here bounds the bytes of its result.
- **What is kept.** The checks do not show that the result is the start of the input, or that the marker is there.
- **The pipeline in `engine.rs`.** The engine appends attachment notes after `truncate_body`, so the body with notes can be longer than `max_chars`. That is the documented design. The checks say nothing about how `limit` is computed, or about the frame cap. Only `process_due` calls the two functions: `process_due_fed` and `process_due_fed_sealed` send a body that neither function has cut.
- **std.** Kani checks against the std of its own toolchain (nightly-2026-08-21), not the std that the daemon is built with. It assumes that an allocation never fails. In the four harnesses with a tag, `Arguments::estimated_capacity` of std is replaced by a constant.
