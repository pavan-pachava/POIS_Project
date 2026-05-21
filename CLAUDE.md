# Cryptographic Minicrypt Explorer

Full-stack educational platform for exploring cryptographic reductions and primitives. No external cryptographic libraries are used—all implementations are educational/toy versions for learning purposes.

## Project Overview

- **Backend**: FastAPI (Python) - cryptographic implementations and API
- **Frontend**: React + Vite - interactive UI for visualization
- **Purpose**: Educational exploration of cryptographic reductions and primitives

## Backend Structure

```
backend/
├── main.py                 # FastAPI app entry point
├── api/
│   ├── models.py          # Pydantic models
│   ├── schemas.py         # Request/response schemas
│   └── routes/            # API endpoints (one per cryptographic topic)
│       ├── prg.py         # Pseudo-random generator
│       ├── prf.py         # Pseudo-random function
│       ├── enc.py         # Encryption
│       ├── cpa.py         # CPA attacks
│       ├── mac.py         # Message authentication codes
│       ├── hash.py        # Hash functions
│       ├── rsa.py         # RSA cryptosystem
│       ├── dh.py          # Diffie-Hellman
│       ├── elgamal.py     # ElGamal (PA#16)
│       ├── sign.py        # Digital signatures
│       ├── attacks.py     # Attack implementations
│       ├── modes.py       # Encryption modes (CBC, CTR, OFB)
│       ├── mpc.py         # Secure multi-party computation
│       ├── cca.py         # CCA attacks
│       ├── build.py       # Component builder
│       └── reduce.py      # Reduction framework
└── core/                  # Core cryptographic implementations
    ├── foundations/       # Basic primitives (AES, DLP)
    ├── pa1_owf_prg/      # One-way functions and PRG
    ├── pa2_prf/          # Pseudo-random functions
    ├── pa3_enc/          # Encryption
    ├── pa4_modes/        # Encryption modes
    ├── pa5_mac/          # Message authentication
    ├── pa10_hmac/        # HMAC
    ├── pa11_dh/          # Diffie-Hellman
    ├── pa12_rsa/         # RSA
    ├── pa13_miller_rabin/ # Miller-Rabin primality
    ├── pa14_crt_attack/  # CRT attack
    ├── pa15_signatures/  # Signatures
    ├── pa16_elgamal/     # ElGamal
    ├── pa17_cca_pkc/     # CCA-secure PKC
    ├── pa18_ot/          # Oblivious transfer
    ├── pa19_secure_and/  # Secure AND gate
    └── pa20_mpc/         # Multi-party computation
```

## Frontend Structure

```
frontend/
├── src/
│   ├── main.tsx          # Entry point
│   ├── App.tsx           # Main app component
│   ├── components/       # React components
│   ├── services/         # API communication
│   └── styles/           # CSS/styling
├── index.html
├── vite.config.ts
└── package.json
```

## Running the Project

### Backend
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Backend runs on `http://127.0.0.1:8000`, frontend on `http://127.0.0.1:5173`.

## Key API Endpoints

All endpoints are `POST`:
- `/api/prg` - Pseudo-random generator
- `/api/prf` - Pseudo-random function
- `/api/encrypt` - Encryption operations
- `/api/mac` - Message authentication codes
- `/api/hash` - Hash functions
- `/api/rsa` - RSA cryptosystem
- `/api/elgamal` - ElGamal (PA#16)
- `/api/dh` - Diffie-Hellman
- `/api/sign` - Digital signatures
- `/api/build` - Component builder
- `/api/reduce` - Reduction framework

Request/response formats defined in `backend/api/schemas.py`.

## Development Notes

- **No external crypto libraries**: All implementations are educational/toy versions
- **Not production-secure**: Designed for learning cryptographic concepts
- **Dynamic UI**: Frontend updates when foundation, primitives, seed, or query/message changes
- **Educational focus**: Each PA (Programming Assignment) module is self-contained

## Testing & Documentation

- See `docs/PA_IMPLEMENTATION_AND_TEST_GUIDE.md` for:
  - PA-by-PA implementation notes
  - API and UI test workflows
  - Expected outcomes

## Common Tasks

- **Add a new cryptographic primitive**: Create new route in `backend/api/routes/` and implementation in `backend/core/`
- **Update API contracts**: Modify `backend/api/schemas.py` for request/response formats
- **Add frontend features**: Work in `frontend/src/components/` and `frontend/src/services/`
- **Debug implementations**: Check test outputs in `docs/PA_IMPLEMENTATION_AND_TEST_GUIDE.md`

## Configuration

- `.env` file for environment variables (check `.gitignore` for sensitive data handling)
- FastAPI runs with `--reload` flag in development
- Frontend uses Vite for fast HMR (Hot Module Replacement)
