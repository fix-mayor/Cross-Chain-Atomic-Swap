
;; title: Cross-Chain-Atomic-Swap
;; title: Cross-Chain-Atomic-Swap
;; Error codes
(define-constant ERR-UNAUTHORIZED u1)
(define-constant ERR-SWAP-NOT-FOUND u2)
(define-constant ERR-ALREADY-CLAIMED u3)
(define-constant ERR-NOT-CLAIMABLE u4)
(define-constant ERR-TIMELOCK-ACTIVE u5)
(define-constant ERR-TIMELOCK-EXPIRED u6)
(define-constant ERR-INVALID-PROOF u7)
(define-constant ERR-INVALID-SIGNATURE u8)
(define-constant ERR-INVALID-HASH u9)
(define-constant ERR-INSUFFICIENT-FUNDS u10)
(define-constant ERR-SWAP-EXPIRED u11)
(define-constant ERR-INVALID-REFUND u12)
(define-constant ERR-INVALID-PARTICIPANT u13)
(define-constant ERR-MIXER-NOT-FOUND u14)
(define-constant ERR-INVALID-FEE u15)
(define-constant ERR-PARTICIPANT-LIMIT-REACHED u16)

;; Configuration constants
(define-constant MAX-TIMEOUT-BLOCKS u1000)
(define-constant MIN-SWAP-AMOUNT u1000)
(define-constant MAX-PARTICIPANTS-PER-MIXER u10)
(define-constant MIXER-FEE-PERCENTAGE u5)  ;; 0.5%
(define-constant PROTOCOL-FEE-PERCENTAGE u2)  ;; 0.2%
(define-constant DEFAULT-QUORUM u2)  ;; Number of required signatures for multi-sig (out of 3)

;; ----- Data Maps and Variables -----

;; Tracks the status of each swap
(define-map swaps
  { swap-id: (buff 32) }
  {
    initiator: principal,
    participant: principal,
    amount: uint,
    hash-lock: (buff 32),
    time-lock: uint,
    swap-token: (string-ascii 32),
    target-chain: (string-ascii 32),
    target-address: (buff 64),
    claimed: bool,
    refunded: bool,
    multi-sig-required: uint,
    multi-sig-provided: uint,
    privacy-level: uint,
    expiration-height: uint,
    swap-fee: uint,
    protocol-fee: uint
  }
)

;; Stores ZK proofs for confidential transactions
(define-map confidential-proofs
  { swap-id: (buff 32) }
  {
    proof-data: (buff 1024),
    verified: bool,
    verification-time: uint
  }
)
