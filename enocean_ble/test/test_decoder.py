from enocean_ble.decoder import PTM215BDecoder
import pytest
import binascii


@pytest.fixture()
def source_address_le():
    return binascii.unhexlify("B819000015E2")


@pytest.fixture()
def input_data():
    return binascii.unhexlify("0CFFDA035D04000011")


@pytest.fixture
def length_field():
    return binascii.unhexlify("0C")


@pytest.fixture
def seq_counter_le():
    return binascii.unhexlify("5D040000")


@pytest.fixture
def sec_key():
    return binascii.unhexlify("3DDA31AD44767AE3CE56DCE2B3CE2ABB")


@pytest.fixture
def type_field():
    return binascii.unhexlify("FF")


@pytest.fixture
def manufacturer_id():
    return binascii.unhexlify("DA03")


@pytest.fixture
def manufacturer_data_wo_signature():
    return binascii.unhexlify("5D04000011")


def test_create_length_field():
    expected_length_field = binascii.unhexlify("0C")
    resulting_length_field = PTM215BDecoder._create_length_field(1, 1, 2, 9)

    assert resulting_length_field == expected_length_field


def test_create_input_data(
    length_field,
    type_field,
    manufacturer_id,
    manufacturer_data_wo_signature,
):
    expected_input_data = binascii.unhexlify("0CFFDA035D04000011")
    resulting_input_data = PTM215BDecoder._create_input_data(
        length_field, type_field, manufacturer_id, manufacturer_data_wo_signature
    )

    assert resulting_input_data == expected_input_data


def test_create_nonce(source_address_le, seq_counter_le):
    expected_nonce = binascii.unhexlify("B819000015E25D040000000000")
    resulting_nonce = PTM215BDecoder._create_nonce(source_address_le, seq_counter_le)

    assert resulting_nonce == expected_nonce
