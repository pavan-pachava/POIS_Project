# Shared Interfaces

## Build API
POST `/api/build`

```json
{
  "foundation": "AES|DLP",
  "source_primitive": "OWF|PRG|PRF|MAC",
  "seed": "hex"
}
```

## Reduce API
POST `/api/reduce`

```json
{
  "foundation": "AES|DLP",
  "source_primitive": "PRG",
  "target_primitive": "PRF",
  "seed": "a3f2",
  "message": "1011"
}
```

## MAC API
POST `/api/mac`

```json
{
  "key": "hex",
  "message": "text",
  "scheme": "prf|cbc",
  "tag": "optional-hex-tag-for-verification"
}
```
