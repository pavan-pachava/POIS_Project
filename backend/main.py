"""FastAPI application entrypoint for the Minicrypt Explorer backend."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import attacks, build, cca, dh, elgamal, enc, hash, mac, modes, mpc, prf, prg, reduce, rsa, sign

app = FastAPI(title="Cryptographic Minicrypt Explorer API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(prg.router, prefix="/api", tags=["prg"])
app.include_router(prf.router, prefix="/api", tags=["prf"])
app.include_router(enc.router, prefix="/api", tags=["encrypt"])
app.include_router(modes.router, prefix="/api", tags=["modes"])
app.include_router(mac.router, prefix="/api", tags=["mac"])
app.include_router(cca.router, prefix="/api", tags=["cca"])
app.include_router(hash.router, prefix="/api", tags=["hash"])
app.include_router(rsa.router, prefix="/api", tags=["rsa"])
app.include_router(elgamal.router, prefix="/api", tags=["elgamal"])
app.include_router(dh.router, prefix="/api", tags=["dh"])
app.include_router(sign.router, prefix="/api", tags=["sign"])
app.include_router(mpc.router, prefix="/api", tags=["mpc"])
app.include_router(build.router, prefix="/api", tags=["build"])
app.include_router(reduce.router, prefix="/api", tags=["reduce"])
app.include_router(attacks.router, prefix="/api", tags=["attacks"])


@app.get("/")
def health_check() -> dict:
    """Simple health check endpoint."""
    return {"status": "ok"}
