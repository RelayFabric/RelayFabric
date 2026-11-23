-------------------------- MODULE SendQueueTrace --------------------------
(* Takes the log of a real run, one line at a time, and lets the model SendQueue
   take the step that the line reports. trace_run.py next to this file runs
   relayfabric_sdk.runner and writes the logs; its docstring says where each
   line is written. TraceLog is the module that the trace check writes from a
   log. *)
EXTENDS SendQueue, TraceLog

VARIABLE traceAt

Event(e) ==
  \* the read loop
  \/ e.action = "Receive" /\ e.by = "reader" /\ Receive(e.corr)
  \/ e.action = "Lock" /\ e.by = "reader" /\ OfferLock
  \/ e.action = "Check" /\ e.by = "reader" /\ OfferCheck
       /\ e.corr = cur.corr /\ e.found = (cur.corr \in pending)
  \/ e.action = "Size" /\ e.by = "reader" /\ (OfferRoom \/ OfferFull) /\ e.size = Len(queue)
  \/ e.action = "Put" /\ e.by = "reader" /\ OfferPut /\ e.corr = cur.corr
  \/ e.action = "Add" /\ e.by = "reader" /\ OfferAdd /\ e.corr = cur.corr
  \/ e.action = "Unlock" /\ e.by = "reader" /\ OfferUnlock /\ e.pending = pending
  \/ e.action = "Busy" /\ e.by = "reader" /\ AnswerBusy /\ e.corr = cur.corr
  \/ e.action = "Shutdown" /\ e.by = "reader" /\ ReceiveShutdown
  \/ e.action = "PutStop" /\ e.by = "reader" /\ Close
  \/ e.action = "Exit" /\ e.by = "reader" /\ Exit
  \/ e.action = "Lost" /\ e.by = "reader" /\ ConnectionLost
  \* the worker
  \/ e.action = "Get" /\ e.by = "worker" /\ Get /\ taken' # Stop /\ e.corr = taken'.corr
  \/ e.action = "GetStop" /\ e.by = "worker" /\ Get /\ taken' = Stop
  \/ e.action = "Dispatch" /\ e.by = "worker" /\ Dispatch /\ e.corr = taken.corr
  \/ e.action = "Lock" /\ e.by = "worker" /\ ReleaseLock
  \/ e.action = "Discard" /\ e.by = "worker" /\ ReleaseDiscard /\ e.corr = taken.corr
  \/ e.action = "Unlock" /\ e.by = "worker" /\ ReleaseUnlock /\ e.pending = pending

TraceInit == Init /\ traceAt = 0

TraceNext ==
  /\ traceAt < Len(TraceLog)
  /\ Event(TraceLog[traceAt + 1])
  /\ traceAt' = traceAt + 1

TraceUnfinished == traceAt < Len(TraceLog)
=============================================================================
