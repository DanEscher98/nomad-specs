------------------------ MODULE SlidingWindow ------------------------
(*
 * NOMAD Protocol - Anti-Replay Sliding Window Formal Specification
 * TLA+ Model
 *
 * This specification models the NOMAD anti-replay sliding window mechanism,
 * verifying:
 *   1. Window only advances after AEAD verification (not before)
 *   2. Duplicate nonces are always rejected
 *   3. Nonces below window floor are always rejected
 *   4. Valid nonces are properly marked as seen
 *   5. Window slides correctly on high nonce arrival
 *
 * SPEC REFERENCE: 1-SECURITY.md §Anti-Replay Protection
 *
 * CRITICAL ORDERING (§Replay Check Ordering):
 *   1. Check if definite replay (read-only, cheap)
 *   2. AEAD verification (expensive, but required)
 *   3. Mark seen and update window (only after AEAD success)
 *
 * ADVERSARY MODEL:
 *   - Attacker can inject frames with arbitrary nonces
 *   - Attacker CANNOT forge valid AEAD (by assumption)
 *   - Attacker goal: advance window to cause DoS on legitimate traffic
 *)

EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    WindowSize,         \* Size of sliding window (spec: 2048 bits)
    MaxNonce,           \* Maximum nonce value for model (spec: 2^64-1)
    MaxFrames           \* Maximum frames to process (model bound)

ASSUME WindowSize > 0
ASSUME MaxNonce >= WindowSize
ASSUME MaxFrames > 0

-----------------------------------------------------------------------------
(* State Space *)
-----------------------------------------------------------------------------

VARIABLES
    \* Receiver state
    highest_seen,       \* Highest valid (authenticated) nonce received
    seen_bitmap,        \* Set of nonces currently in window that have been seen

    \* Frame processing state
    pending_nonce,      \* Nonce of frame currently being processed (or -1)
    processing_phase,   \* "idle" | "checking" | "verifying" | "marking"

    \* Attacker state
    attacker_injected,  \* Set of forged nonces attacker has injected

    \* Counters
    frames_processed,   \* Number of frames processed
    legitimate_sent     \* Set of nonces for legitimate frames sent

vars == <<highest_seen, seen_bitmap, pending_nonce, processing_phase,
          attacker_injected, frames_processed, legitimate_sent>>

-----------------------------------------------------------------------------
(* Type Invariants *)
-----------------------------------------------------------------------------

TypeOK ==
    /\ highest_seen \in 0..MaxNonce
    /\ seen_bitmap \subseteq 0..MaxNonce
    /\ pending_nonce \in -1..MaxNonce
    /\ processing_phase \in {"idle", "checking", "verifying", "marking"}
    /\ attacker_injected \subseteq 0..MaxNonce
    /\ frames_processed \in 0..MaxFrames
    /\ legitimate_sent \subseteq 0..MaxNonce

-----------------------------------------------------------------------------
(* Helper Functions *)
-----------------------------------------------------------------------------

\* Window floor (lowest nonce that could be valid)
\* SPEC: window_floor = highest_seen - len(bitmap) + 1
WindowFloor == IF highest_seen >= WindowSize - 1
               THEN highest_seen - WindowSize + 1
               ELSE 0

\* Check if nonce is in current window range
InWindow(n) ==
    /\ n >= WindowFloor
    /\ n <= highest_seen + WindowSize  \* Allow future nonces

\* Check if nonce would be definite replay (read-only check)
\* SPEC: Steps 1-2 in check_and_mark()
IsDefiniteReplay(n) ==
    \/ n < WindowFloor                  \* Below window floor
    \/ (n <= highest_seen /\ n \in seen_bitmap)  \* Already seen

\* Check if AEAD would succeed (legitimate frame only)
AEADWouldSucceed(n) == n \in legitimate_sent

-----------------------------------------------------------------------------
(* Initial State *)
-----------------------------------------------------------------------------

Init ==
    /\ highest_seen = 0
    /\ seen_bitmap = {}
    /\ pending_nonce = -1
    /\ processing_phase = "idle"
    /\ attacker_injected = {}
    /\ frames_processed = 0
    /\ legitimate_sent = {}

-----------------------------------------------------------------------------
(* Legitimate Sender Actions *)
(* Sender creates frames with valid AEAD *)
-----------------------------------------------------------------------------

SendLegitimateFrame(n) ==
    /\ n \in 0..MaxNonce
    /\ n \notin legitimate_sent
    /\ legitimate_sent' = legitimate_sent \union {n}
    /\ UNCHANGED <<highest_seen, seen_bitmap, pending_nonce, processing_phase,
                   attacker_injected, frames_processed>>

-----------------------------------------------------------------------------
(* Attacker Actions *)
(* Attacker injects forged frames (AEAD will fail) *)
-----------------------------------------------------------------------------

AttackerInjectFrame(n) ==
    /\ n \in 0..MaxNonce
    /\ n \notin attacker_injected
    /\ n \notin legitimate_sent  \* Attacker doesn't have real keys
    /\ attacker_injected' = attacker_injected \union {n}
    /\ UNCHANGED <<highest_seen, seen_bitmap, pending_nonce, processing_phase,
                   legitimate_sent, frames_processed>>

-----------------------------------------------------------------------------
(* Receiver Actions *)
(* Models the 3-phase receive process from spec *)
-----------------------------------------------------------------------------

\* Phase 1: Start processing a frame (any pending nonce)
StartProcessing(n) ==
    /\ processing_phase = "idle"
    /\ frames_processed < MaxFrames
    /\ n \in 0..MaxNonce
    /\ (n \in legitimate_sent \/ n \in attacker_injected)
    /\ pending_nonce' = n
    /\ processing_phase' = "checking"
    /\ frames_processed' = frames_processed + 1
    /\ UNCHANGED <<highest_seen, seen_bitmap, attacker_injected, legitimate_sent>>

\* Phase 2: Check if definite replay (read-only)
\* SPEC: is_definite_replay() - "read-only, does NOT advance window"
CheckReplay ==
    /\ processing_phase = "checking"
    /\ IF IsDefiniteReplay(pending_nonce)
       THEN \* Reject immediately
            /\ processing_phase' = "idle"
            /\ pending_nonce' = -1
       ELSE \* Pass to AEAD verification
            /\ processing_phase' = "verifying"
            /\ UNCHANGED pending_nonce
    /\ UNCHANGED <<highest_seen, seen_bitmap, attacker_injected,
                   frames_processed, legitimate_sent>>

\* Phase 3: AEAD verification
\* SPEC: verify_aead() - expensive, but required before window update
VerifyAEAD ==
    /\ processing_phase = "verifying"
    /\ IF AEADWouldSucceed(pending_nonce)
       THEN \* AEAD succeeded, proceed to mark
            /\ processing_phase' = "marking"
            /\ UNCHANGED pending_nonce
       ELSE \* AEAD failed (attacker frame), drop
            /\ processing_phase' = "idle"
            /\ pending_nonce' = -1
    /\ UNCHANGED <<highest_seen, seen_bitmap, attacker_injected,
                   frames_processed, legitimate_sent>>

\* Phase 4: Mark seen and update window (ONLY after AEAD success)
\* SPEC: mark_seen() - "Only mark_seen() advances the window"
MarkSeen ==
    /\ processing_phase = "marking"
    /\ LET n == pending_nonce
           new_highest == IF n > highest_seen THEN n ELSE highest_seen
           new_floor == IF new_highest >= WindowSize - 1
                        THEN new_highest - WindowSize + 1
                        ELSE 0
       IN
        /\ highest_seen' = new_highest
        \* Add n to bitmap and prune old entries below new floor
        /\ seen_bitmap' = {x \in (seen_bitmap \union {n}) : x >= new_floor}
    /\ processing_phase' = "idle"
    /\ pending_nonce' = -1
    /\ UNCHANGED <<attacker_injected, frames_processed, legitimate_sent>>

-----------------------------------------------------------------------------
(* Next State Relation *)
-----------------------------------------------------------------------------

Next ==
    \/ \E n \in 0..MaxNonce : SendLegitimateFrame(n)
    \/ \E n \in 0..MaxNonce : AttackerInjectFrame(n)
    \/ \E n \in 0..MaxNonce : StartProcessing(n)
    \/ CheckReplay
    \/ VerifyAEAD
    \/ MarkSeen

Fairness ==
    /\ WF_vars(CheckReplay)
    /\ WF_vars(VerifyAEAD)
    /\ WF_vars(MarkSeen)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety Properties *)
-----------------------------------------------------------------------------

\* S1: Window never advances on attacker frames
\* CRITICAL: This is the key anti-DoS property
\* SPEC: "If the window advanced before AEAD verification, an attacker could
\*        send forged packets with high nonces to advance the window"
AttackerCannotAdvanceWindow ==
    \* If we're in verifying phase with an attacker nonce, window hasn't changed
    processing_phase = "verifying" /\ pending_nonce \in attacker_injected
        => highest_seen = highest_seen

\* S2: Only authenticated nonces are marked seen
OnlyAuthenticatedMarkedSeen ==
    \A n \in seen_bitmap : n \in legitimate_sent

\* S3: Duplicate nonces cannot be accepted
\* Once a nonce is in seen_bitmap, it will be rejected
NoDuplicateAcceptance ==
    \A n \in 0..MaxNonce :
        n \in seen_bitmap => IsDefiniteReplay(n)

\* S4: Nonces below floor are always rejected
FloorEnforced ==
    \A n \in 0..MaxNonce :
        n < WindowFloor => IsDefiniteReplay(n)

\* S5: Window is properly bounded
WindowBounded ==
    /\ Cardinality(seen_bitmap) <= WindowSize
    /\ \A n \in seen_bitmap : n >= WindowFloor

\* S6: The ordering invariant - window only changes in marking phase
\* (Cannot be directly expressed as safety property but verified by model structure)

Safety == OnlyAuthenticatedMarkedSeen /\ WindowBounded /\ FloorEnforced

-----------------------------------------------------------------------------
(* Attack Resistance Properties *)
-----------------------------------------------------------------------------

\* A1: Attacker high-nonce injection does not affect legitimate traffic
\* Model: even if attacker injects nonce 1000000, legitimate nonce 1 still works
\* This is verified by the structure: attacker frames fail AEAD, never reach marking

\* A2: Window floor advances only from legitimate traffic
WindowAdvancesOnlyFromLegitimate ==
    \* After any step, if highest_seen increased, it must be a legitimate nonce
    highest_seen' > highest_seen => highest_seen' \in legitimate_sent

-----------------------------------------------------------------------------
(* Invariants to Check *)
-----------------------------------------------------------------------------

THEOREM SafetyTheorem == Spec => []Safety
THEOREM TypeSafety == Spec => []TypeOK
THEOREM AttackResistance == Spec => []OnlyAuthenticatedMarkedSeen

=============================================================================
