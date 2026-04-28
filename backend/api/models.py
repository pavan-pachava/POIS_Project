"""Pydantic request models for API routes."""

from typing import Literal

from pydantic import BaseModel, Field


class PRGRequest(BaseModel):
    seed: str = Field(..., description="Hex seed")
    output_bits: int = Field(32, ge=1, le=4096)
    g: int = Field(5, ge=2)
    p: int = Field(2147483647, ge=3)


class PRFRequest(BaseModel):
    key: str
    query: str
    g: int = 5
    p: int = 2147483647


class EncryptRequest(BaseModel):
    key: str
    message: str


class MACRequest(BaseModel):
    key: str
    message: str
    scheme: Literal["prf", "cbc"] = Field("prf", description="MAC scheme: 'prf' or 'cbc'")
    tag: str | None = Field(None, description="Optional tag for verification mode")


class HashRequest(BaseModel):
    message: str
    scheme: Literal["md", "dlp", "hmac", "birthday"] = "md"
    key: str | None = None
    truncate_bits: int = Field(12, ge=4, le=24)
    max_trials: int = Field(2000, ge=10, le=50000)
    tag: str | None = None


class BuildRequest(BaseModel):
    foundation: str
    source_primitive: str
    seed: str


class ReduceRequest(BaseModel):
    foundation: str
    source_primitive: str
    target_primitive: str
    seed: str
    message: str
    reduction_mode: Literal["forward", "both", "backward"] = "forward"


class ModesRequest(BaseModel):
    mode: Literal["cbc", "ctr", "ofb"] = "cbc"
    key: str
    data: str = Field("", description="UTF-8 plaintext or hex ciphertext based on operation")
    iv_or_nonce: str = Field("00000001", description="4-byte hex IV/nonce")
    operation: Literal["encrypt", "decrypt"] = "encrypt"
    input_format: Literal["text", "hex"] = "text"


class CCARequest(BaseModel):
    operation: Literal["encrypt", "decrypt"] = "encrypt"
    key_enc: str
    key_mac: str
    message: str | None = None
    r: str | None = None
    ciphertext: str | None = None
    tag: str | None = None


class RSARequest(BaseModel):
    operation: Literal["keygen", "encrypt", "decrypt"] = "keygen"
    bits: int = Field(32, ge=16, le=128)
    n: int | None = None
    e: int | None = None
    d: int | None = None
    p: int | None = None
    q: int | None = None
    message_int: int | None = None
    ciphertext_int: int | None = None


class ElGamalRequest(BaseModel):
    operation: Literal["keygen", "encrypt", "decrypt"] = "keygen"
    bits: int = Field(16, ge=8, le=128)
    g: int = Field(2, ge=2)
    p: int | None = None
    y: int | None = None
    x: int | None = None
    message_int: int | None = None
    c1: int | None = None
    c2: int | None = None


class DHRequest(BaseModel):
    p: int = 2147483647
    g: int = 5
    a: int | None = None
    b: int | None = None


class SignRequest(BaseModel):
    scheme: Literal["rsa", "elgamal"] = "rsa"
    operation: Literal["sign", "verify"] = "sign"
    message: str
    signature: int | None = None
    signature_r: int | None = None
    signature_s: int | None = None
    n: int | None = None
    e: int | None = None
    d: int | None = None
    p: int | None = None
    g: int | None = None
    x: int | None = None
    y: int | None = None


class MPCRequest(BaseModel):
    operation: Literal["ot", "and", "xor", "not", "2pc", "millionaire", "equality", "addition"] = "2pc"
    m0: int = 0
    m1: int = 1
    choice_bit: int = Field(0, ge=0, le=1)
    a_bit: int = Field(0, ge=0, le=1)
    b_bit: int = Field(1, ge=0, le=1)
    x_value: int = 0
    y_value: int = 0
    bit_width: int = Field(8, ge=1, le=32)
    elgamal_bits: int = Field(16, ge=8, le=128)
    elgamal_g: int = Field(2, ge=2)


class CpaAttackRequest(BaseModel):
    key: str = "1a2b3c4d"
    m0: str = "left-message"
    m1: str = "right-message"
    challenge_bit: int | None = Field(default=None, ge=0, le=1)
    nonce: int = Field(7, ge=0, le=2**31 - 1)
    trials: int = Field(10, ge=1, le=1000)


class IvReuseAttackRequest(BaseModel):
    key: str = "1a2b3c4d"
    known_plaintext: str = "known-prefix-plaintext"
    target_plaintext: str = "target-prefix-secret"
    nonce: int = Field(7, ge=0, le=2**31 - 1)


class MalleabilityAttackRequest(BaseModel):
    key: str = "1a2b3c4d"
    plaintext: str = "pay=100"
    flip_mask_hex: str = "01"
    nonce: int = Field(9, ge=0, le=2**31 - 1)
