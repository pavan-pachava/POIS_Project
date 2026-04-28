"""Pydantic models for API payloads."""

from pydantic import BaseModel, Field


class PRGRequest(BaseModel):
    seed: int = Field(ge=0)
    out_bits: int = Field(default=64, ge=1, le=512)


class PRFRequest(BaseModel):
    key: int = Field(ge=0)
    query_bits: str = Field(default="1011")


class EncryptRequest(BaseModel):
    key: int = Field(ge=0)
    message: str
    nonce: int = Field(default=7, ge=0)


class MACRequest(BaseModel):
    key: int = Field(ge=0)
    message: str


class HashRequest(BaseModel):
    message: str


class ReduceRequest(BaseModel):
    source: str
    target: str
