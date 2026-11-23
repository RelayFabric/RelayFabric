---------------------------- MODULE SendQueue ----------------------------
(* The send queue and its worker thread in sdk/python/relayfabric_sdk/runner.py.

   Two threads share one _SendQueue:
     - the read loop, the `while True` loop at the end of run_plugin, which calls
       _enqueue -> _SendQueue.offer for each send or send_direct frame, and
       _SendQueue.close for the shutdown frame;
     - the worker, _sender_loop, which calls _SendQueue.get, _dispatch, and
       _SendQueue.release.

   Each action below is one step that no other thread can split in the code:
   taking or leaving _SendQueue._lock, one read or write of _SendQueue._pending
   made while that lock is held, or one call on _SendQueue._q, which queue.Queue
   makes indivisible with its own mutex. The comment on each action quotes the
   line of runner.py that it stands for. VERIFY.md next to this file says which
   code the model covers and how to keep the two in step. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  Corrs,      \* the corr values that the daemon uses in a run, as numbers above 0
  MaxQueue,   \* SEND_QUEUE_MAX: _SendQueue._maxsize, the bound that offer keeps
  MaxFrames,  \* how many send and send_direct frames the daemon sends in a run
  Faults      \* deliberate breaks, by name; {} is the code as it is written

\* A frame with no corr. _SendQueue._key returns None for it, and offer never dedups it.
NoCorr == 0

\* The shutdown sentinel: the None that close() puts on the queue.
Stop == [id |-> 0, corr |-> NoCorr]

VARIABLES
  reader,      \* where the read loop is
  cur,         \* the frame that the read loop is handling; id counts the frames
  outcome,     \* what offer returns for cur: "queued", "duplicate" or "full"
  received,    \* how many send and send_direct frames the read loop has read
  lock,        \* who holds _SendQueue._lock: "free", "reader" or "worker"
  pending,     \* _SendQueue._pending
  queue,       \* the items in _SendQueue._q, oldest first
  worker,      \* where _sender_loop is
  taken,       \* the item that _sender_loop took last
  accepted,    \* history: each frame that offer put on the queue, in order
  dispatched,  \* history: each frame that _dispatch was called with, in order
  refused,     \* history: each frame with a corr that offer answered "full"
  busy         \* history: each frame that got a "plugin busy" delivery_result

vars == <<reader, cur, outcome, received, lock, pending, queue, worker, taken,
          accepted, dispatched, refused, busy>>

Init ==
  /\ reader = "read" /\ cur = Stop /\ outcome = "none" /\ received = 0
  /\ lock = "free" /\ pending = {} /\ queue = <<>>
  /\ worker = "get" /\ taken = Stop
  /\ accepted = <<>> /\ dispatched = <<>> /\ refused = <<>> /\ busy = <<>>

-----------------------------------------------------------------------------
(* The read loop. *)

\* `frame = read_frame(sock)` returns a send or send_direct frame, and _enqueue
\* calls send_q.offer(kind, frame). offer treats the two kinds alike.
Receive(c) ==
  /\ reader = "read" /\ received < MaxFrames
  /\ received' = received + 1
  /\ cur' = [id |-> received + 1, corr |-> c]
  /\ outcome' = "none"
  /\ reader' = "lock"
  /\ UNCHANGED <<lock, pending, queue, worker, taken, accepted, dispatched, refused, busy>>

\* offer: `with self._lock:`
OfferLock ==
  /\ reader = "lock"
  /\ IF "NoLock" \in Faults THEN UNCHANGED lock ELSE lock = "free" /\ lock' = "reader"
  /\ reader' = IF cur.corr = NoCorr THEN "size" ELSE "check"
  /\ UNCHANGED <<cur, outcome, received, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* offer: `if corr is not None and corr in self._pending: return "duplicate"`
OfferCheck ==
  /\ reader = "check"
  /\ IF cur.corr \in pending /\ "NoDedup" \notin Faults
       THEN outcome' = "duplicate" /\ reader' = "unlock"
       ELSE outcome' = outcome /\ reader' = "size"
  /\ UNCHANGED <<cur, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* offer: `if self._q.qsize() >= self._maxsize:` finds room. The put is a later
\* step, so the worker can take an item between the two.
OfferRoom ==
  /\ reader = "size"
  /\ Len(queue) < MaxQueue \/ "NoBound" \in Faults
  /\ reader' = "put"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* offer: `if self._q.qsize() >= self._maxsize: return "full"`
OfferFull ==
  /\ reader = "size"
  /\ Len(queue) >= MaxQueue /\ "NoBound" \notin Faults
  /\ outcome' = "full"
  /\ refused' = IF cur.corr = NoCorr THEN refused ELSE Append(refused, cur)
  /\ pending' = IF "ReserveOnFull" \in Faults /\ cur.corr # NoCorr
                  THEN pending \cup {cur.corr} ELSE pending
  /\ reader' = "unlock"
  /\ UNCHANGED <<cur, received, lock, queue, worker, taken, accepted, dispatched, busy>>

\* offer: `self._q.put_nowait((kind, frame))`. _q has no bound of its own, so
\* this put never raises queue.Full.
OfferPut ==
  /\ reader = "put"
  /\ queue' = Append(queue, cur)
  /\ accepted' = Append(accepted, cur)
  /\ outcome' = "queued"
  /\ reader' = IF cur.corr = NoCorr THEN "unlock" ELSE "add"
  /\ UNCHANGED <<cur, received, lock, pending, worker, taken, dispatched, refused, busy>>

\* offer: `self._pending.add(corr)`
OfferAdd ==
  /\ reader = "add"
  /\ pending' = pending \cup {cur.corr}
  /\ reader' = "unlock"
  /\ UNCHANGED <<cur, outcome, received, lock, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* offer: the end of `with self._lock:`, and the return to _enqueue
OfferUnlock ==
  /\ reader = "unlock"
  /\ lock' = IF "NoLock" \in Faults THEN lock ELSE "free"
  /\ reader' = IF outcome = "full" /\ cur.corr # NoCorr /\ "NoBusy" \notin Faults
                 THEN "busy" ELSE "read"
  /\ UNCHANGED <<cur, outcome, received, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* _enqueue: `_send_frame(delivery_result(corr, False, "plugin busy"))`
AnswerBusy ==
  /\ reader = "busy"
  /\ busy' = Append(busy, cur)
  /\ reader' = "read"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused>>

\* `frame = read_frame(sock)` returns the shutdown frame
ReceiveShutdown ==
  /\ reader = "read"
  /\ reader' = "close"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* close: `self._q.put(None)`. _q has no bound of its own, so this put never waits.
\* The fault CloseWaits is a _q that has the bound: there the put waits for room.
Close ==
  /\ reader = "close"
  /\ "CloseWaits" \in Faults => Len(queue) < MaxQueue
  /\ queue' = IF "StopJumpsQueue" \in Faults THEN <<Stop>> \o queue ELSE Append(queue, Stop)
  /\ reader' = "join"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, worker, taken,
                 accepted, dispatched, refused, busy>>

\* `sender.join(timeout=2.0)` returns, because the worker ended or because the two
\* seconds passed. Then bridge.stop() runs, and `sys.exit(0)` ends the process.
Exit ==
  /\ reader = "join"
  /\ reader' = "exited"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

\* read_frame raises EOFError, OSError or ValueError: `sys.exit(1)`, with no close and no join
ConnectionLost ==
  /\ reader = "read"
  /\ reader' = "exited"
  /\ UNCHANGED <<cur, outcome, received, lock, pending, queue, worker, taken,
                 accepted, dispatched, refused, busy>>

-----------------------------------------------------------------------------
(* The worker, _sender_loop. It is a daemon thread, so it stops where it is when
   the read loop ends the process. *)

Alive == reader # "exited"

\* `item = send_q.get()`, and `if item is None: return` for the sentinel
Get ==
  /\ Alive /\ worker = "get" /\ queue # <<>>
  /\ LET item == IF "Lifo" \in Faults THEN queue[Len(queue)] ELSE Head(queue)
         rest == IF "Lifo" \in Faults THEN SubSeq(queue, 1, Len(queue) - 1) ELSE Tail(queue)
     IN  /\ queue' = rest
         /\ taken' = item
         /\ worker' = IF item = Stop THEN "done" ELSE "dispatch"
         /\ pending' = IF "EarlyRelease" \in Faults THEN pending \ {item.corr} ELSE pending
  /\ UNCHANGED <<reader, cur, outcome, received, lock, accepted, dispatched, refused, busy>>

\* `_dispatch(kind, frame)` calls bridge.handle_send or bridge.handle_send_direct.
\* The call can take long, and it can never return.
Dispatch ==
  /\ Alive /\ worker = "dispatch"
  /\ dispatched' = Append(dispatched, taken)
  /\ worker' = "release"
  /\ UNCHANGED <<reader, cur, outcome, received, lock, pending, queue, taken,
                 accepted, refused, busy>>

\* The bridge call returned or raised. `finally: send_q.release(...)`, and in
\* release: `with self._lock:`
ReleaseLock ==
  /\ Alive /\ worker = "release" /\ lock = "free"
  /\ lock' = "worker"
  /\ worker' = "discard"
  /\ UNCHANGED <<reader, cur, outcome, received, pending, queue, taken,
                 accepted, dispatched, refused, busy>>

\* release: `self._pending.discard(corr)`
ReleaseDiscard ==
  /\ Alive /\ worker = "discard"
  /\ pending' = IF "NoRelease" \in Faults THEN pending ELSE pending \ {taken.corr}
  /\ worker' = "unlock"
  /\ UNCHANGED <<reader, cur, outcome, received, lock, queue, taken,
                 accepted, dispatched, refused, busy>>

\* release: the end of `with self._lock:`, and back to the top of `while True:`
ReleaseUnlock ==
  /\ Alive /\ worker = "unlock"
  /\ lock' = "free"
  /\ worker' = "get"
  /\ UNCHANGED <<reader, cur, outcome, received, pending, queue, taken,
                 accepted, dispatched, refused, busy>>

\* The process is gone. This step changes nothing; without it TLC would report
\* the end of a run as a deadlock.
Exited == reader = "exited" /\ UNCHANGED vars

Next ==
  \/ \E c \in Corrs \cup {NoCorr} : Receive(c)
  \/ OfferLock \/ OfferCheck \/ OfferRoom \/ OfferFull \/ OfferPut \/ OfferAdd \/ OfferUnlock
  \/ AnswerBusy
  \/ ReceiveShutdown \/ Close \/ Exit \/ ConnectionLost
  \/ Get \/ Dispatch \/ ReleaseLock \/ ReleaseDiscard \/ ReleaseUnlock
  \/ Exited

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The rules. *)

\* The worker has taken a frame and has not released its corr yet.
Holding == worker \in {"dispatch", "release", "discard"}

\* How many sends for corr c are waiting in the queue or with the worker.
Copies(c) ==
  Cardinality({i \in DOMAIN queue : queue[i].corr = c})
    + (IF Holding /\ taken.corr = c THEN 1 ELSE 0)

\* A corr is never queued or in flight twice at the same time.
OneSendPerCorr == \A c \in Corrs : Copies(c) <= 1

\* A corr is in _pending only while a send for it is queued or in flight.
NoStuckCorr == \A c \in pending : Copies(c) >= 1

\* The bridge gets the sends in the order in which offer accepted them.
InOrder ==
  /\ Len(dispatched) <= Len(accepted)
  /\ \A i \in DOMAIN dispatched : dispatched[i] = accepted[i]

\* When the worker ends on the shutdown sentinel, the bridge has been given
\* every send that offer accepted.
DrainedAtStop == worker = "done" => dispatched = accepted

\* Before the read loop reads its next frame, each send with a corr that was
\* refused for a full queue has its "plugin busy" delivery_result.
BusyAnswered == reader = "read" => busy = refused

\* No more than SEND_QUEUE_MAX sends wait in the queue.
Bounded == Cardinality({i \in DOMAIN queue : queue[i] # Stop}) <= MaxQueue

\* close() never has to wait for a send that the bridge is still working on:
\* while the worker is in _dispatch, the read loop can always take its Close step.
\* (The comment on close() promises more, that it never waits at all. Close has
\* no condition but its place in the read loop, so that holds as well.)
CloseNeverWaits == (reader = "close" /\ worker = "release") => ENABLED Close

(* A rule that the code as it is written breaks. It is in a config of its own,
   NoSendAbandoned.cfg, so that SendQueue.cfg can pass. VERIFY.md tells the story. *)

\* When the process exits, the bridge has been given every send that offer accepted.
NoSendAbandoned == reader = "exited" => dispatched = accepted
=============================================================================
