# PA Implementation And Test Guide

This document explains what each PA currently does in this repository, how to test it, and what to expect from a correct run.

## 1) Quick verification workflow

1. Start backend in one terminal
   - uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
2. Start frontend in another terminal
   - cd frontend
   - npm run dev
3. Run backend tests
   - /home/vikash/Desktop/git_folders/POIS_Project/.venv/bin/python -m pytest -q
4. Run frontend production build
   - cd frontend
   - npm run build

Expected:
- All tests pass.
- Frontend build completes successfully.

## 2) Role of the UI in this project

The UI is not only a viewer; it is the primary teaching workflow that ties together build, reduction, proof narration, and attack simulation.

Main UI responsibilities:
- Drive a strict learning flow: Foundation -> Primitive A (build) -> Primitive B (reduce).
- Show reduction traceability with ordered step logs and method labels.
- Visualize special structures when available:
  - GGM tree-style branching for PRF-related traces.
  - Block-level views for mode operations.
  - Merkle-Damgard chain steps for hash flows.
- Provide interactive attack and MPC demos with parameterized forms.
- Normalize backend outputs in result/steps shape for readable display.

Primary UI files:
- frontend/src/App.jsx
- frontend/src/components/FoundationToggle.jsx
- frontend/src/components/BuildPanel.jsx
- frontend/src/components/ReducePanel.jsx
- frontend/src/components/ProofPanel.jsx
- frontend/src/components/AttackDemosPanel.jsx
- frontend/src/services/cryptoAPI.js

## 3) UI workflow (how to test from UI)

Use this sequence for end-to-end UI verification:

1. Start backend and frontend
  - uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
  - cd frontend
  - npm run dev
2. Open the app and run the core flow
  - Set foundation in Foundation toggle.
  - In Build panel, select Source primitive A and fill key/seed.
  - Confirm artifact and intermediate steps appear.
  - In Reduce panel, select Target primitive B and fill message/query input.
  - Confirm reduction steps, specialized views (if applicable), and final output appear.
3. Validate proof view
  - Confirm Proof panel chain and reduction step text match Reduce panel output.
4. Validate demos
  - Scroll to Attack Demonstrations and run each card:
    - CPA attack
    - IV reuse
    - Malleability
    - Birthday
    - PA18-PA20 MPC demo
5. Negative behavior checks
  - Intentionally change required inputs (for example invalid tags in verify flows) and confirm user-visible error or rejection states.

Expected UI behavior:
- Column 1 and Column 2 stay synchronized.
- Column 2 consumes build artifact produced in Column 1.
- Result and explanation steps are rendered for successful responses.
- Errors are shown as inline alert blocks without page crash.

## 4) Bidirectional reduction policy (assignment requirement)

Implemented rule:
- Bidirectional reductions are enabled only where required:
  - PA1: PRG -> OWF
  - PA2: PRF -> PRG
  - PA10 bridge: MAC <-> CRHF via HMAC bridge logic
- All other reductions are forward-only.

Relevant files:
- backend/core/reductions/router.py
- backend/core/reduce_executor.py

How to test:
- Call /api/reduce with reduction_mode=both and the relevant source/target pair.

Expected:
- Required reverse pairs return steps.
- Non-required reverse pairs return no route.

## 5) PA-by-PA implementation and testing

## PA0: Interactive Minicrypt explorer scaffold

What it does:
- Two-column workflow:
  - Column 1 builds primitive A from foundation.
  - Column 2 reduces A to B.
- Proof panel and attack demo panel.

Where implemented:
- frontend/src/App.jsx
- frontend/src/components/BuildPanel.jsx
- frontend/src/components/ReducePanel.jsx
- frontend/src/components/ProofPanel.jsx
- backend/api/routes/build.py
- backend/api/routes/reduce.py

How to test:
1. Open frontend and change foundation/source/target.
2. Verify both columns update live.

Expected:
- No crash on primitive changes.
- Build and reduce sections show steps and outputs.

## PA1: OWF and PRG

What it does:
- Forward:
  - OWF via modular exponentiation.
  - PRG via iterative OWF and bit extraction.
- Backward witness:
  - OWF from PRG by defining f(s)=G(s).

Where implemented:
- backend/core/pa1_owf_prg/owf.py
- backend/core/pa1_owf_prg/prg.py
- backend/api/routes/prg.py

How to test:
- API:
  - POST /api/prg with seed and output_bits
- Reduction reverse:
  - POST /api/reduce with source_primitive=PRG, target_primitive=OWF, reduction_mode=both

Expected:
- PRG returns output_bits and output_hex.
- Reverse route PRG -> OWF appears with corresponding steps.

## PA2: PRF via GGM and backward PRG from PRF

What it does:
- Forward:
  - GGM-style PRF from PA1 PRG.
- Backward:
  - G(s)=F_s(0^n)||F_s(1^n).

Where implemented:
- backend/core/pa2_prf/ggm_prf.py
- backend/api/routes/prf.py

How to test:
- API:
  - POST /api/prf with key and query
- Reduction reverse:
  - POST /api/reduce with source_primitive=PRF, target_primitive=PRG, reduction_mode=both

Expected:
- /api/prf returns output and query.
- Reverse route PRF -> PRG is available only in bidirectional mode.

## PA3: CPA encryption and attack demos

What it does:
- CPA-style toy encryption/decryption.
- Attack demos: cpa game simulation, nonce reuse leakage, malleability flip.

Where implemented:
- backend/core/pa3_enc/enc.py
- backend/core/pa3_enc/dec.py
- backend/core/pa3_cpa_enc/attacks.py
- backend/api/routes/enc.py
- backend/api/routes/attacks.py

How to test:
- API:
  - POST /api/encrypt
  - POST /api/cpa-attack
  - POST /api/iv-reuse
  - POST /api/malleability

Expected:
- /api/encrypt returns r and ciphertext.
- Attack endpoints return structured result and explanation steps.

## PA4: CBC, CTR, OFB modes

What it does:
- Mode encrypt/decrypt demonstrations for CBC, CTR, OFB.

Where implemented:
- backend/core/pa4_modes/cbc.py
- backend/core/pa4_modes/ctr.py
- backend/core/pa4_modes/ofb.py
- backend/api/routes/modes.py

How to test:
- POST /api/modes with mode and operation.

Expected:
- CBC decrypt returns original plaintext for matching key/iv.
- CTR/OFB decrypt path reconstructs plaintext text field.

## PA5: MAC

What it does:
- PRF-MAC and CBC-MAC with verify mode.

Where implemented:
- backend/core/pa5_mac/prf_mac.py
- backend/core/pa5_mac/cbc_mac.py
- backend/core/pa5_mac/service.py
- backend/api/routes/mac.py

How to test:
- POST /api/mac with scheme=prf or cbc.
- Send tag to verify path.

Expected:
- Tag generated in sign mode.
- verify returns valid=true for matching message/tag/key.

## PA6: CCA symmetric encryption (Encrypt-then-MAC)

What it does:
- Encrypt then MAC and verify-before-decrypt behavior.

Where implemented:
- backend/core/pa6_cca/cca_enc.py
- backend/api/routes/cca.py

How to test:
1. POST /api/cca operation=encrypt
2. POST /api/cca operation=decrypt with returned r,ciphertext,tag

Expected:
- Decrypt accepts untampered payload.
- Tampering ciphertext or tag yields rejection.

## PA7: Merkle-Damgard hash

What it does:
- MD-strengthening style toy hash chain.

Where implemented:
- backend/core/pa7_md/merkle_damgard.py
- backend/api/routes/hash.py with scheme=md

How to test:
- POST /api/hash with scheme=md.

Expected:
- Digest returned with chain steps.

## PA8: DLP-style hash

What it does:
- DLP-inspired exponent/hash mapping.

Where implemented:
- backend/core/pa8_dlp_hash/dlp_hash.py
- backend/api/routes/hash.py with scheme=dlp

How to test:
- POST /api/hash with scheme=dlp.

Expected:
- Digest returned under result.digest.

## PA9: Birthday attack

What it does:
- Collision search on truncated outputs.

Where implemented:
- backend/core/pa9_birthday/attack.py
- backend/api/routes/hash.py with scheme=birthday

How to test:
- POST /api/hash with scheme=birthday and truncate_bits.

Expected:
- Result indicates whether collision found and number of attempts.

## PA10: HMAC and CRHF-MAC bridge

What it does:
- HMAC generation/verification.
- Bidirectional bridge helpers:
  - CRHF -> MAC via HMAC construction.
  - MAC -> CRHF via keyed compression witness.

Where implemented:
- backend/core/pa10_hmac/hmac.py
- backend/api/routes/hash.py with scheme=hmac

How to test:
- POST /api/hash with scheme=hmac, key, message.
- POST /api/hash with scheme=hmac, key, message, tag for verify.
- Reduction bridge:
  - POST /api/reduce with source_primitive=MAC, target_primitive=HASH, reduction_mode=both

Expected:
- HMAC tag generated and verify valid=true for matching tag.
- MAC -> CRHF reverse route appears only in bidirectional mode.

## PA11: Diffie-Hellman

What it does:
- Safe-prime group generation.
- Alice/Bob step functions and exchange consistency.
- MITM demo and CDH brute-force demo helpers.

Where implemented:
- backend/core/pa11_dh/diffie_hellman.py
- backend/api/routes/dh.py

How to test:
- POST /api/dh with optional a,b.

Expected:
- shared_secret computed and consistent=true.

## PA12: RSA

What it does:
- RSA keygen with CRT params.
- Textbook enc/dec with custom modular exponentiation.
- PKCS#1 v1.5 helpers and toy Bleichenbacher demo helpers.

Where implemented:
- backend/core/pa12_rsa/rsa.py
- backend/api/routes/rsa.py

How to test:
1. POST /api/rsa keygen
2. POST /api/rsa encrypt
3. POST /api/rsa decrypt

Expected:
- decrypt plaintext equals encrypted message_int.

## PA13: Miller-Rabin

What it does:
- Miller-Rabin test, prime generation, Carmichael demo, benchmark helper.

Where implemented:
- backend/core/pa13_miller_rabin/miller_rabin.py

How to test:
- Via unit tests and via RSA/DH key generation flows.

Expected:
- Known prime reports probable prime.
- 561 rejected by Miller-Rabin helper demo.

## PA14: CRT and Hastad attack

What it does:
- General CRT solver.
- RSA CRT decryption helper.
- Hastad attack helper and boundary estimate.

Where implemented:
- backend/core/pa14_crt_attack/crt.py

How to test:
- Use direct unit tests and helper calls from python shell/tests.

Expected:
- CRT recombination satisfies congruences.

## PA15: Signatures

What it does:
- RSA hash-then-sign and verify.
- Raw RSA forgery demo helper.
- EUF-CMA demo helper.
- ElGamal sign/verify.

Where implemented:
- backend/core/pa15_signatures/signatures.py
- backend/api/routes/sign.py

How to test:
- POST /api/sign with scheme=rsa, operation=sign
- POST /api/sign with scheme=rsa, operation=verify

Expected:
- Valid signature verifies true.
- Tampered message verification fails.

## PA16: ElGamal

What it does:
- ElGamal keygen/encrypt/decrypt over PA11-style group.
- Malleability and IND-CPA helper demos.

Where implemented:
- backend/core/pa16_elgamal/elgamal.py
- backend/api/routes/elgamal.py

How to test:
- POST /api/elgamal keygen
- POST /api/elgamal encrypt/decrypt

Expected:
- Decrypt returns original message_int modulo p.

## PA17: CCA-secure PKC

What it does:
- Encrypt-then-Sign flow.
- Verify-then-Decrypt enforcement.
- CCA2 demo helper and contrast with plain ElGamal malleability.

Where implemented:
- backend/core/pa17_cca_pkc/cca_pkc.py

How to test:
- Direct via python unit-style invocation of helper functions.

Expected:
- Tampered ciphertext is rejected before decryption in PA17 flow.

## PA18: OT

What it does:
- Bellare-Micali style 1-out-of-2 OT flow.

Where implemented:
- backend/core/pa18_ot/ot.py
- backend/api/routes/mpc.py operation=ot

How to test:
- POST /api/mpc with operation=ot and choice_bit.

Expected:
- Receiver obtains only selected message branch.

## PA19: Secure gates

What it does:
- AND from OT plus XOR and NOT gate helpers.

Where implemented:
- backend/core/pa19_secure_and/secure_and.py
- backend/api/routes/mpc.py operations and xor and not

How to test:
- POST /api/mpc with operation=and|xor|not.

Expected:
- Output bits match truth tables.

## PA20: Secure circuit evaluation

What it does:
- Generic Circuit DAG evaluator using secure gates.
- Mandatory circuits:
  - millionaire
  - equality
  - addition

Where implemented:
- backend/core/pa20_mpc/mpc.py
- backend/api/routes/mpc.py operations millionaire, equality, addition

How to test:
- POST /api/mpc with operation=millionaire/equality/addition and x_value, y_value, bit_width.

Expected:
- millionaire returns x_gt_y.
- equality returns equal boolean.
- addition returns sum_mod_2n.

## 6) PA-by-PA UI testing map

This map shows how each PA is tested from the UI workflow.

- PA0:
  - UI path: entire app flow (Foundation toggle + Build + Reduce + Proof + Demos).
  - Check: layout and data flow are coherent, no render/runtime crash.
- PA1:
  - UI path: Build panel with source=PRG, then Reduce panel with target=OWF.
  - Check: PRG artifact generated; reduction path and output visible.
- PA2:
  - UI path: Build panel with source=PRF, then Reduce panel with target=PRG.
  - Check: GGM-related steps appear; output updates when query/message changes.
- PA3:
  - UI path: Attack Demonstrations cards (CPA, IV reuse, malleability).
  - Check: result JSON and step explanations reflect selected payload.
- PA4:
  - UI path: Build/Reduce flows targeting CBC, CTR, OFB.
  - Check: block-level step output and final output update correctly.
- PA5:
  - UI path: Build/Reduce with target=MAC.
  - Check: tag-like output appears and changes with message/key edits.
- PA6:
  - UI path: Build/Reduce path including CCA target.
  - Check: steps include verify-before-decrypt style narrative from backend.
- PA7:
  - UI path: Build/Reduce with HASH-oriented flow.
  - Check: chain-like steps rendered; digest/output shown.
- PA8:
  - UI path: Build/Reduce with DLPHASH target.
  - Check: output value shown in Final Output and changes with inputs.
- PA9:
  - UI path: Attack Demonstrations Birthday card.
  - Check: attempts/collision metadata populated in result panel.
- PA10:
  - UI path: Build/Reduce including HMAC/HASH/MAC transitions.
  - Check: expected bridge-style reduction steps appear where route exists.
- PA11:
  - UI path: Build/Reduce with DH source or target.
  - Check: DH-related outputs and step trace displayed.
- PA12:
  - UI path: Build/Reduce with RSA source or target.
  - Check: RSA outputs appear and respond to message/key-size changes.
- PA13:
  - UI path: indirect via RSA/DH flows.
  - Check: UI remains stable while backend primality-driven operations execute.
- PA14:
  - UI path: indirect via RSA-related flows.
  - Check: reduction and output rendering remain correct for CRT-backed operations.
- PA15:
  - UI path: Build/Reduce with SIGN source or target.
  - Check: signature-related final output shown and step narrative present.
- PA16:
  - UI path: Build/Reduce with ElGamal-linked transitions where routed.
  - Check: output and trace update correctly.
- PA17:
  - UI path: mostly indirect (backend helpers), observed through compatible PKC reductions.
  - Check: UI renders backend responses and rejection/errors safely.
- PA18:
  - UI path: Attack Demonstrations MPC card with operation=ot.
  - Check: selected branch behavior reflected in result.
- PA19:
  - UI path: Attack Demonstrations MPC card with operation=and/xor/not.
  - Check: gate outputs match expected truth-table behavior for input bits.
- PA20:
  - UI path: Attack Demonstrations MPC card with operation=millionaire/equality/addition.
  - Check: result booleans/sums match x, y, and bit-width inputs.

## 7) Automated test mapping

Main tests:
- tests/test_pa_unit_comprehensive.py
- tests/test_pa_independent_smoke.py
- tests/test_reductions.py
- tests/test_api_response_shapes.py
- tests/test_prg.py
- tests/test_prf.py
- tests/test_enc.py
- tests/test_mac.py
- tests/test_hash.py
- tests/test_edge_cases_and_attacks.py

Recommended command:
- /home/vikash/Desktop/git_folders/POIS_Project/.venv/bin/python -m pytest -q

Expected:
- All tests pass.

## 8) Frontend integration checks

Where integrated:
- frontend/src/App.jsx
- frontend/src/components/BuildPanel.jsx
- frontend/src/components/ReducePanel.jsx
- frontend/src/components/ProofPanel.jsx
- frontend/src/components/AttackDemosPanel.jsx
- frontend/src/services/cryptoAPI.js

How to test:
1. npm run dev and open app.
2. Verify build and reduce cards update on input changes.
3. Verify attack demo cards return JSON result and step traces.
4. Production build check:
   - cd frontend
   - npm run build

Expected:
- Build succeeds.
- UI renders without runtime crashes.
- Endpoint calls return data in expected result/steps shape.