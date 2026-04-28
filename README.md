# Cryptographic Minicrypt Explorer

Full-stack educational explorer for Minicrypt reductions.

## Folder structure

```text
crypto-project/
├── frontend/
├── backend/
│   ├── api/
│   └── core/
├── shared/
├── tests/
└── docs/
```

## Backend (FastAPI)

### Install and run

```bash
cd /POIS_Project
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### Available endpoints

- `POST /api/prg`
- `POST /api/prf`
- `POST /api/encrypt`
- `POST /api/mac`
- `POST /api/hash`
- `POST /api/rsa`
- `POST /api/elgamal` (PA#16)
- `POST /api/dh`
- `POST /api/sign`
- `POST /api/build`
- `POST /api/reduce`

## Frontend (React + Vite)

### Install and run

```bash
cd /POIS_Project/frontend
npm install
npm run dev
```

Frontend runs at `http://127.0.0.1:5173` and calls backend at `http://127.0.0.1:8000`.

## Notes

- No cryptographic libraries are used.
- Implementations are educational/toy versions and not production secure.
- UI updates dynamically when foundation, primitives, seed, or query/message changes.

## Detailed PA Guide

- See `docs/PA_IMPLEMENTATION_AND_TEST_GUIDE.md` for PA-by-PA implementation notes, API and UI test workflows, and expected outcomes.