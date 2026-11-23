# Verification record: the send queue and its worker thread

This record covers `_SendQueue` and the code in `run_plugin` that uses it, in
`sdk/python/relayfabric_sdk/runner.py`. Read it before you change that code, and
follow "Steps for a change" below.

Two threads share one `_SendQueue`. The read loop (the `while True` loop at the end of
`run_plugin`) calls `offer` for each `send` and `send_direct` frame, and `close` for
the `shutdown` frame. The worker (`_sender_loop`) calls `get`, `_dispatch`, and
`release`. The verification checks six rules in every order in which the steps of
the two threads can happen, within the bounds given below.

- **Model check:** `SendQueue.tla` with `SendQueue.cfg`, a TLA+ model of the two
  threads. It passes: 132,180 states, about 2 seconds.
- **Trace check:** `trace_run.py` runs the real code in six scenarios and logs each
  step. `SendQueueTrace.tla` checks that the model can take the same steps in the
  same order. It passes on all six logs.
- **Finding F1:** the code breaks a seventh rule, `CloseNeverWaits`. See "Known
  weaknesses".

Last checked against the code on 2026-11-23, with the `tla-check` skill of the
`formal-proofs` plugin, version 0.4.0 (TLC 1.7.4), and CPython 3.14.4.

## Covered code

```
covered:
  - sdk/python/relayfabric_sdk/runner.py f9a1d56fcdf3
    > SEND_QUEUE_MAX = 256
    > class _SendQueue:
    > self._q = queue.Queue(maxsize=maxsize)
    > self._pending = set()
    > self._lock = threading.Lock()
    > def _key(frame):
    > def offer(self, kind, frame):
    > with self._lock:
    > if corr is not None and corr in self._pending:
    > self._q.put_nowait((kind, frame))
    > except queue.Full:
    > self._pending.add(corr)
    > def release(self, corr):
    > with self._lock:
    > self._pending.discard(corr)
    > def get(self):
    > return self._q.get()
    > def close(self):
    > self._q.put(None)
  - sdk/python/relayfabric_sdk/runner.py 6ae4e3c8cce0
    > send_q = _SendQueue(maxsize=SEND_QUEUE_MAX)
    > def _enqueue(kind, frame):
    > outcome = send_q.offer(kind, frame)
    > _send_frame(delivery_result(corr, False, "plugin busy"))
    > def _dispatch(kind, frame):
    > bridge.handle_send(frame)
    > handle_send_direct(frame)
    > def _sender_loop():
    > item = send_q.get()
    > if item is None:
    > _dispatch(kind, frame)
    > send_q.release(
    > sender = threading.Thread(target=_sender_loop
    > frame = read_frame(sock)
    > except (EOFError, OSError, ValueError) as e:
    > sys.exit(1)
    > _enqueue("send", frame)
    > _enqueue("send_direct", frame)
    > send_q.close()
    > sender.join(timeout=2.0)
    > stop()
    > sys.exit(0)
```

`drift.sh` reads this block. It is in the `maintain-formal-verification` skill of the
`formal-proofs` plugin; run it from the repo root. It reports a stretch whose text
changed since the last sync, and names a cited line that is missing or moved. The
hash after each path is written by `drift.sh --sync`.

A pass of the checks on a verification that no one updated says nothing about a
change to the covered code. The model is a description: it keeps passing when the
code moves away from it. Only the trace check runs the code, and only in six
scenarios: five fixed orders of steps, and one order that differs from run to run.

The model also assumes code that is not in this repo: `queue.Queue` and
`threading.Lock` of the Python standard library. It assumes that `put_nowait` raises
`queue.Full` at `maxsize`, that `put` waits at `maxsize`, that `get` waits on an empty
queue, that each of those calls is one indivisible step, and that the queue hands
out the oldest item first.

## Why this target

The code promises, in the docstring of `run_plugin`, the docstring of the module,
and the comments of the `shutdown` branch: a re-dispatch of a queued or in-flight
corr is dropped; an overflow is answered with `plugin busy`; one worker keeps the
sends in order; and sends that are already queued drain before the plugin exits.
The daemon re-dispatches a delivery when no result arrives within 60 seconds, so
these promises decide whether a message goes out once, twice, or never.

The closest tests are in `sdk/python/tests/test_runner.py`:

- `SendQueueTests.test_duplicate_corr_is_dropped_until_released` calls `offer`,
  `get`, and `release` on one thread, in one fixed order, and asserts the strings
  that `offer` returns.
- `SendDedupIntegrationTests.test_redispatch_of_an_in_flight_corr_is_dispatched_once`
  runs `run_plugin` with the worker held inside `handle_send`, and asserts that the
  bridge got corr 1 and corr 2 once each. That is one order of steps.

The cases that they do not reach:

1. The worker finishes a send while `offer` is between `put_nowait` and
   `self._pending.add(corr)`. `offer` holds `_lock` to make this safe. With the lock
   removed from `offer` (`breaks/no_lock.patch`), all 29 tests still pass.
2. Whether the worker releases a corr at all. With the `release` call removed from
   `_sender_loop` (`breaks/no_release.patch`), all 29 tests still pass, and every later
   re-dispatch of a corr that was sent once is dropped.
3. A `shutdown` frame that arrives while the queue is at its bound. No test does
   this, and this is where finding F1 is.

## Why a TLA+ model

The question is whether steps of two threads can happen in a bad order. A checker
that runs the real code under every order would be the first choice. For Python
threads there is no established one: `interleave-test` 0.1.0 and `ploom` 0.1.1 exist,
each with one or two releases in 2026, and `ploom` does not see the standard
`queue` and `threading` classes. Neither was tried. So the check is a TLA+ model,
tied to the code in two ways: the hashes in the covered block, and the trace check.

## Which code is which part of the model

All code is in `sdk/python/relayfabric_sdk/runner.py`.

| Code | Model (`SendQueue.tla`) | Log line (`trace_run.py`) |
|------|-------------------------|---------------------------|
| read loop: `frame = read_frame(sock)` returns a `send` or `send_direct` frame; `_SendQueue._key` | `Receive(c)`; a frame with no corr is `NoCorr`, 0 | `Receive` |
| `offer`: `with self._lock:` | `OfferLock`, `OfferUnlock`; variable `lock` | `Lock`, `Unlock` by the reader |
| `offer`: `corr in self._pending` | `OfferCheck`; variable `pending` | `Check` |
| `offer`: `self._q.put_nowait((kind, frame))` | `OfferPut`; variable `queue` | `Put` |
| `offer`: `except queue.Full: return "full"` | `OfferFull` | none: the trace spec infers it |
| `offer`: `self._pending.add(corr)` | `OfferAdd` | `Add` |
| `_enqueue`: `_send_frame(delivery_result(corr, False, "plugin busy"))` | `AnswerBusy` | `Busy` |
| read loop: the `shutdown` frame | `ReceiveShutdown` | `Shutdown` |
| `close`: `self._q.put(None)` | `Close`; the sentinel is `Stop` | `PutStop` |
| read loop: `sender.join(timeout=2.0)`, `stop()`, `sys.exit(0)` | `Exit` | `Exit` |
| read loop: `except (EOFError, OSError, ValueError)`, `sys.exit(1)` | `ConnectionLost` | `Lost` |
| `_sender_loop`: `item = send_q.get()`, `if item is None: return` | `Get`; variable `taken` | `Get`, `GetStop` |
| `_sender_loop`: `_dispatch(kind, frame)`, which calls `bridge.handle_send` or `bridge.handle_send_direct` | `Dispatch` | `Dispatch` |
| `release`: `with self._lock:` | `ReleaseLock`, `ReleaseUnlock` | `Lock`, `Unlock` by the worker |
| `release`: `self._pending.discard(corr)` | `ReleaseDiscard` | `Discard` |
| `SEND_QUEUE_MAX` | constant `MaxQueue` | `MAX_QUEUE` |

The model has one reader and one worker, because in the code only the read loop
calls `offer` and `close`, and only `_sender_loop` calls `get` and `release`. The
worker is a daemon thread, so in the model it takes no step after `Exit` or
`ConnectionLost`.

`trace_run.py` does not change `runner.py`. It swaps the three objects that
`_SendQueue.__init__` builds for ones that log: `_q` and `_pending` for subclasses
of the classes that `__init__` chose, and `_lock` for a wrapper around the same
lock. So it depends on those three names, on the name `_SendQueue`, on
`runner.read_frame`, and on the thread name that ends in `-sender`.

The model does not lean on the GIL. Each step that it treats as indivisible is a
take or a release of `_lock`, a read or a write of `_pending` made while `_lock` is
held, or one call on `_q`, which `queue.Queue` guards with its own mutex.

## The rules

| Rule | What it promises | The harm when it breaks |
|------|------------------|-------------------------|
| `OneSendPerCorr` | A corr is never waiting in the queue or with the worker twice at the same time. | The same message goes out to the backend twice, and the backlog of a slow backend fills with duplicates. |
| `NoStuckCorr` | A corr is in `_pending` only while a send for it is queued or in flight. | Every later re-dispatch of that corr is dropped as a duplicate, so the message is never sent and the daemon never gets a result for it. |
| `InOrder` | The bridge gets the sends in the order in which `offer` accepted them. | Messages reach the other network out of order. |
| `DrainedAtStop` | When the worker ends on the shutdown sentinel, the bridge has been given every send that `offer` accepted. | A send that was accepted just before shutdown is dropped without a result. |
| `BusyAnswered` | Before the read loop reads its next frame, each send with a corr that was refused for a full queue has its `plugin busy` result. | The daemon is not told to back off, and waits 60 seconds for a send that the plugin never queued. |
| `Bounded` | No more than `SEND_QUEUE_MAX` sends wait in the queue. | A slow backend lets the backlog, and the memory of the plugin, grow without limit. |

A send is "in flight" from the moment the worker takes it until the worker has
discarded its corr. In the model that is `Holding`, which names the places of the
worker: `dispatch`, `release`, and `discard`.

Bounds of the committed config: corr values 1 and 2 and frames with no corr, a
queue bound of 2, and five `send` or `send_direct` frames in a run, then `shutdown`
or a lost connection at any point. One larger run also passed on 2026-11-23, with
three corr values, a queue bound of 3, and seven frames: 14,328,165 states, 15
seconds on 24 cores.

## Run the checks

Run the TLA+ parts with the `tla-check` skill of the `formal-proofs` plugin. This
record was written with version 0.4.0. The skill needs only Java, and its own text
gives the commands; they are not copied here, because they change between
releases. The `statechart` skill of the same plugin does not apply: the model is
far above its 500 states.

1. **Model check.** Check `sdk/python/formal/send_queue/SendQueue.tla`. The config
   `SendQueue.cfg` is next to it. A pass is exit code 0, with `Model checking
   completed. No error has been found.` and 132,180 distinct states.
2. **The pass is not empty.** With the same skill, list how often each action ran.
   Each of the 18 actions under `Next` must be in the list with a count above 0.
   No action is switched off in the committed config, so an action with `0:0` is
   an error in the model. `Exited` finds no new state by design, and still shows
   how often it ran.
3. **Trace check.** Write the logs with the real code, from the repo root. It needs
   Python 3.10 or later with `cbor2`, like the SDK tests, and takes about 5
   seconds:

   ```sh
   LOGS=$(mktemp -d)
   python sdk/python/formal/send_queue/trace_run.py "$LOGS"
   ```

   It writes `redispatch.log`, `overflow.log`, `free_running.log`,
   `connection_lost.log`, `join_timeout.log`, and `close_waits.log`. With the trace
   check of the `tla-check` skill, check each log against
   `sdk/python/formal/send_queue/SendQueueTrace.tla`. The config `SendQueueTrace.cfg`
   is next to it. A pass is exit code 0 and `ok: the model follows all N events`
   for each of the six logs. `free_running.log` differs from run to run on purpose:
   its two threads meet in a random order. Five logs are the same in every run.
   Keep a log that the model cannot follow, because the log is the reproduction.
4. **The tests of the repo.** From `sdk/python`:
   `PYTHONPATH=. python -m unittest tests.test_runner`.

## Steps for a change

These steps are for the author of a change to the covered code, and for a reviewer
of a change that has not landed yet. A change that landed without them goes to the
`maintain-formal-verification` skill.

1. Run `drift.sh` from the repo root. It names each covered stretch that changed.
   For a stretch with a cited line that it cannot find, it names only the first
   such line, so read the whole diff of `runner.py`, not only that line.
2. Read the change against the table above and against `SendQueue.tla`. A change
   matters to the model when it adds, removes, or reorders a step of either thread;
   when it changes what is done while `_lock` is held; when it changes the class
   or the bound of `_q`; when it changes what is put on the queue or taken from it;
   or when a new caller or a new thread touches `_SendQueue`. `drift.sh` cannot see
   a new caller outside the covered stretches, so search for one.
3. **A change that alters nothing that the model describes**, such as a rename, a
   comment, or the text of a message, needs only this: read it against the model;
   update the cited lines in the covered block, the lines that the comments of
   `SendQueue.tla` quote, and the names in `trace_run.py`, when the change touched
   them; run the trace check, which shows that the code still takes the same
   steps; then sync (step 9).
4. Otherwise, update the verification from the code, before you run anything. Do
   not shape the update by what makes the check pass. Change the actions in
   `SendQueue.tla`, and list a new action under `Next`; change `Event` in
   `SendQueueTrace.tla` and the log lines in `trace_run.py` when a step was added or
   removed. Keep one action for one step of the code, and no action for a step
   that the code does not take.
5. When the change adds a step, a rule that names steps must name the new step
   too. `Holding` names the places of the worker between `Get` and `ReleaseDiscard`:
   a new place of the worker there belongs in it. That does not weaken the rule,
   as long as its plain sentence in the table stays true. Change the sentence of a
   rule only when the change alters the promise on purpose, and say so in the
   change.
6. Run the model check, and check that the pass is not empty.
7. When a rule breaks, replay the path against the code before you decide. Write
   each step of the path in the words of the code. Then make the real code take
   those steps: a bridge whose `handle_send` waits on a `threading.Event` holds the
   worker at a step, as the scenarios in `trace_run.py` do. To hold the read loop
   inside `offer`, give a subclass of `_SendQueue` a `_lock` or a `_pending` that
   waits, the way `_TracedSendQueue` in `trace_run.py` gives it ones that log. If a
   step cannot happen in the code, the model is wrong: fix the model, and say what
   was wrong. If every step can happen, the change has a bug.
8. Run the trace check on logs from the changed code. When `trace_run.py` itself
   stops, with an `AttributeError` or with `scenario stalled`, the code no longer
   fits the script: a name that it depends on changed, or a scenario no longer
   plays out as its docstring says. When the model cannot take an event, the code
   and the model differ at that event: the code does something that the model
   does not describe, or the model has a step that the code does not take or does
   not log. Decide which from the code. Then confirm that the checks can still
   fail: run each row of the fault table below, and delete one line from a log and
   see the trace check exit with 1.
9. Only then sync: run `drift.sh --sync sdk/python/formal/send_queue/VERIFY.md` from
   the repo root, check that the line numbers it prints are the stretches you
   meant, and commit the record with the verification. Run `--sync` only after you
   have confirmed that the verification describes the changed code.

When a change has a bug, the updated verification stays with that change, as a
patch or on its branch, and no one syncs it.

## Deliberate breaks

Each fault is a switch in the model: a name in the constant `Faults`, which is `{}`
in the committed configs. With the fault check of the `tla-check` skill, switch on
one fault and require one rule; each row must print `ok: fault ... breaks ...`.
Checked on 2026-11-23: each fault breaks the rules in its row, and no other rule.

| Fault | The break, in the words of the code | Rule that it must break |
|-------|-------------------------------------|-------------------------|
| `NoDedup` | `offer` skips the `corr in self._pending` check | `OneSendPerCorr` |
| `EarlyRelease` | the corr leaves `_pending` when the worker takes the frame, before `_dispatch` | `OneSendPerCorr` |
| `NoLock` | `offer` does not take `_lock` | `NoStuckCorr` |
| `NoRelease` | `_sender_loop` does not discard the corr after `_dispatch` | `NoStuckCorr` |
| `ReserveOnFull` | `offer` adds the corr to `_pending` also when `put_nowait` raises `queue.Full` | `NoStuckCorr` |
| `Lifo` | the worker takes the newest item, not the oldest | `InOrder` |
| `Lifo` | the same | `DrainedAtStop` |
| `StopJumpsQueue` | `close` puts the sentinel at the front of the queue | `DrainedAtStop` |
| `NoBusy` | `_enqueue` sends no `plugin busy` result | `BusyAnswered` |
| `NoBound` | `put_nowait` never raises `queue.Full` | `Bounded` |

Every action of the model runs in the committed config. The faults are branches
inside actions, not actions of their own, so none of them shows as an action that
never ran.

The trace check runs the real code, so its breaks are patch files in
`sdk/python/formal/send_queue/breaks/`. From the repo root, apply one, write the
logs, run the trace check, and take the patch out again:

```sh
git apply sdk/python/formal/send_queue/breaks/no_lock.patch
python sdk/python/formal/send_queue/trace_run.py "$LOGS"
git apply -R sdk/python/formal/send_queue/breaks/no_lock.patch
```

| Patch | The break | What must fail |
|-------|-----------|----------------|
| `no_lock.patch` | `offer` without `with self._lock:` | The trace check exits with 1 on all six logs. The 29 tests of `tests/test_runner.py` pass. |
| `no_release.patch` | `_sender_loop` without the `release` call | The trace check exits with 1 on `redispatch.log`, `overflow.log`, `free_running.log`, and `close_waits.log`. The 29 tests pass. |

The shortest way to see the trace check fail is to delete one line from a log: it
must exit with 1 and name the event that the model cannot take.

## Known weaknesses

These are cases that the model includes and shows to break. They are apart from
what the check leaves out, which is the next section. Each rule here has a config
of its own, so that `SendQueue.cfg` can pass. For each of them, exit code 12 is the
expected result.

### F1: `close()` waits when the queue is full (a bug)

Rule `CloseNeverWaits`: the `shutdown` frame never has to wait for a send that the
bridge is still working on. In the model: while the worker is in `_dispatch`, the
read loop can always take its `Close` step.

The comment on `close` says that the sentinel "bypasses the bound so shutdown can
never block", and the comment in the `shutdown` branch says that a wedged send "is
abandoned at the join timeout rather than hanging exit". The code does not do
that: `close` calls `self._q.put(None)`, and `put` waits for as long as the queue is
at `maxsize`.

The path, with the real bound of 256:

1. A send is inside `bridge.handle_send`, and the backend is slow or stuck.
2. The daemon keeps sending, until 256 more sends wait in the queue.
3. The daemon sends `shutdown`. The read loop calls `send_q.close()`.
4. `self._q.put(None)` waits for room. Only the worker makes room, and the worker
   is inside `handle_send`.
5. The read loop stays in `close()`. It does not reach `sender.join(timeout=2.0)`,
   `bridge.stop()`, or `sys.exit(0)` until `handle_send` returns. It also reads no
   more frames, so it answers no ping and does not see the connection close.

The harm: with a full queue and a stuck send, the plugin does not stop on
`shutdown`. `bridge.stop()` does not run, and the process stays until something
kills it. A plugin that the daemon started is killed when the daemon exits, about
half a second after it sends `shutdown` (`switchyardd/src/main.rs`). A plugin that
the daemon did not start, such as one under systemd, has nothing that kills it.

How to see it:

- In the model: check `SendQueue.tla` with the config `CloseNeverWaits.cfg`. TLC
  reports `Invariant CloseNeverWaits is violated`. The shortest path has 16 states.
- In the real code: `trace_run.py` prints, for the scenario `close_waits`, that
  `run_plugin` has not exited 3 seconds after the `shutdown` frame. Check
  `close_waits.log` against `SendQueueTrace.tla` with the config
  `CloseNeverWaitsTrace.cfg`: exit code 12, on the state that the log leads to.

The rule can hold. On a scratch copy of the model, checked on 2026-11-23, `Close`
without its wait (the line `Len(queue) < MaxQueue`) keeps `CloseNeverWaits` and the
six rules, in 141,322 states. That is a `close` that does what its comment says.

When `close` is fixed: update `Close` in `SendQueue.tla` from the new code, move
`CloseNeverWaits` into `SendQueue.cfg` and `SendQueueTrace.cfg`, delete
`CloseNeverWaits.cfg` and `CloseNeverWaitsTrace.cfg`, and update the scenario
`close_waits` and this section.

### W1: sends that were accepted can be dropped at exit (by design)

Rule `NoSendAbandoned`: when the process exits, the bridge has been given every
send that `offer` accepted. It breaks in two ways, and the code means both: the
read loop loses the daemon connection and calls `sys.exit(1)` with sends still
queued; or `sender.join(timeout=2.0)` gives up while a send is still inside the
bridge, and `sys.exit(0)` ends the worker with sends still queued.

The harm: the daemon gets no result for those sends. It sends them again after
its 60 second window, to the plugin when it runs again.

How to see it: check `SendQueue.tla` with the config `NoSendAbandoned.cfg`. TLC
reports `Invariant NoSendAbandoned is violated`. The shortest path has 6 states, and
ends with a lost connection. The logs `connection_lost.log` and `join_timeout.log`
are real runs of the two ways.

## What the check does not cover

- **Whether a send ever happens.** The rules say what never happens. No rule says
  that a queued send is dispatched in the end. A `handle_send` that never returns
  stops every later send, while the read loop keeps answering pings.
- **A worker that dies.** `_dispatch` catches `Exception`. A `SystemExit` raised
  inside `handle_send` ends the worker thread, and then nothing empties the queue.
  The model has no such step.
- **The bridge.** What `handle_send` does, its own threads, and the result that it
  writes. A plugin whose `handle_send` returns before the result is known, such as
  LXMF with its own fan-out, has its corr released at that return, not at the
  result.
- **The two kinds of frame.** The model treats `send` and `send_direct` alike, as
  `offer` does. A bridge with no `handle_send_direct` is not modeled.
- **A corr that cannot be hashed.** `_key` treats it as no corr, and `release`
  returns for it before it takes the lock. The model has only the frame with no
  corr, for which `release` takes the lock and discards nothing.
- **Writes to the daemon socket.** `_send_frame`, the write lock of the bridge, and
  the answer to a ping. The model treats the `plugin busy` write as a step that
  always succeeds.
- **`bridge.stop()` while a send is in flight.** After the join timeout, `stop()`
  runs on the read loop while the worker can still be inside `handle_send`. The
  model has `Exit` as one step.
- **The rest of `run_plugin`:** the environment, the handshake, the config, and the
  frames that are not `send`, `send_direct`, or `shutdown`.
- **The daemon:** its reclaim window, its retries, and what it does with a
  `plugin busy` result.
- **More than one reader or worker.** The model has one of each.
- **The standard library.** `queue.Queue` and `threading.Lock` are assumed to work
  as documented.
- **Sizes above the bounds.** The model compares the length of the queue with the
  bound and nothing else, so a bound of 2 stands for 256. That is an argument, not
  a proof.
- **Runs that no scenario made.** The trace check shows that six real runs stay
  inside the model. It does not show that the code never leaves the model. The
  model check tries every order of the steps of the model; the trace check tries
  only the orders that its runs happened to take.
