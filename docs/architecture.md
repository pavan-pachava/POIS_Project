# Architecture

- `frontend/`: React + Vite app with a two-column reduction UI.
- `backend/`: FastAPI API plus modular educational crypto implementations.
- `backend/core/`: Pure crypto and reduction logic.
- `backend/core/pa16_elgamal/`: Explicit PA#16 ElGamal implementation (keygen, encrypt, decrypt).
- `backend/api/`: HTTP routes and request models.
- `shared/`: Shared constants and API interface notes.
