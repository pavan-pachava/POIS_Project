from backend.core.pa7_md.merkle_damgard import toy_hash


def test_hash_output_shape():
    digest = toy_hash("abc")["digest"]
    assert len(digest) == 8
