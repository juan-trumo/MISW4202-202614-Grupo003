from common.hmac_utils import (
    canonicalize,
    load_partner_keys,
    missing_fields,
    sign_payload,
    unknown_fields,
    verify_signature,
)

PAYLOAD = {
    "partner_uuid": "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11",
    "quote_id": "Q-1",
    "holder_id": "C-001",
    "holder_name": "Ana Gómez",
    "premium": "125000.00",
    "coverage": "50000000.00",
    "currency": "COP",
    "issued_at": "2026-09-25T12:00:00Z",
    "nonce": "0b8f7a2e-4c1d-4e5f-9a6b-7c8d9e0f1a2b",
}


def test_canonico_es_independiente_del_orden():
    reordered = dict(reversed(list(PAYLOAD.items())))
    assert canonicalize(PAYLOAD) == canonicalize(reordered)
    assert b" " not in canonicalize({"a": 1, "b": 2})
    assert "Gómez".encode() in canonicalize(PAYLOAD)


def test_firma_valida_se_acepta():
    assert verify_signature("k", PAYLOAD, sign_payload("k", PAYLOAD))
    assert verify_signature("k", PAYLOAD, sign_payload("k", PAYLOAD).upper())


def test_cualquier_alteracion_invalida_la_firma():
    signature = sign_payload("k", PAYLOAD)
    for field, value in [("premium", "1.00"), ("coverage", "1.00"), ("holder_name", "Otro")]:
        assert not verify_signature("k", {**PAYLOAD, field: value}, signature)


def test_firma_con_otra_clave_se_rechaza():
    assert not verify_signature("key-a", PAYLOAD, sign_payload("key-b", PAYLOAD))


def test_firma_ausente_o_no_ascii_se_rechaza():
    assert not verify_signature("k", PAYLOAD, None)
    assert not verify_signature("k", PAYLOAD, "")
    assert not verify_signature("k", PAYLOAD, "ñ" * 64)


def test_campos_desconocidos_y_faltantes():
    assert unknown_fields({**PAYLOAD, "discount": "10"}) == ["discount"]
    assert unknown_fields(PAYLOAD) == []
    assert missing_fields({k: v for k, v in PAYLOAD.items() if k != "nonce"}) == ["nonce"]


def test_load_partner_keys():
    assert load_partner_keys('{"P-A": "a"}') == {"P-A": b"a"}
    assert load_partner_keys("") == {}
