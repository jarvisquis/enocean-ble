import pytest
from home_assistant_bluetooth import BluetoothServiceInfo

from enocean_ble.decoder import PTM215BDecoder


@pytest.fixture
def manufacturer_id():
    return 0x03DA


@pytest.fixture()
def manufacturer_data(manufacturer_id) -> dict:
    return {manufacturer_id: bytes.fromhex("5D04000011B2FA88FF")}


@pytest.fixture()
def manufacturer_data_w_optional_data(manufacturer_id) -> dict:
    return {manufacturer_id: bytes.fromhex("6304000011123452E05116")}


@pytest.fixture()
def decoder(request):
    raw_data = BluetoothServiceInfo(
        name="ptm216b_test",
        address="E2:15:00:00:19:B8",
        rssi=40,
        manufacturer_data=request.getfixturevalue(request.param),
        service_data={},
        service_uuids=[],
        source="",
    )
    return PTM215BDecoder(raw_data)


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", b"\x0c"),
        ("manufacturer_data_w_optional_data", b"\x0e"),
    ],
    indirect=["decoder"],
)
def test_length_field(decoder, expected_field):
    resulting_field = decoder._length_field
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", bytes.fromhex("0CFFDA035D04000011")),
        (
            "manufacturer_data_w_optional_data",
            bytes.fromhex("0EFFDA0363040000111234"),
        ),
    ],
    indirect=["decoder"],
)
def test_input_data(decoder, expected_field):
    resulting_field = decoder._input_data
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", b""),
        ("manufacturer_data_w_optional_data", bytes.fromhex("1112")),
    ],
    indirect=["decoder"],
)
def test_optional_data(decoder, expected_field):
    resulting_field = decoder.optional_data
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", bytes.fromhex("B819000015E2")),
        ("manufacturer_data_w_optional_data", bytes.fromhex("B819000015E2")),
    ],
    indirect=["decoder"],
)
def test_source_address_le(decoder, expected_field):
    resulting_field = decoder._source_address_le
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", bytes.fromhex("5D040000")),
        ("manufacturer_data_w_optional_data", bytes.fromhex("63040000")),
    ],
    indirect=["decoder"],
)
def test_seq_counter_le(decoder, expected_field):
    resulting_field = decoder._seq_counter_le
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", bytes.fromhex("DA03")),
        ("manufacturer_data_w_optional_data", bytes.fromhex("DA03")),
    ],
    indirect=["decoder"],
)
def test_manufacturer_id_le(decoder, expected_field):
    resulting_field = decoder._manufacturer_id_le
    assert resulting_field == expected_field


@pytest.mark.parametrize(
    "decoder, expected_field",
    [
        ("manufacturer_data", bytes.fromhex("B819000015E25D040000000000")),
        (
            "manufacturer_data_w_optional_data",
            bytes.fromhex("B819000015E263040000000000"),
        ),
    ],
    indirect=["decoder"],
)
def test_get_nonce(decoder, expected_field):
    resulting_field = decoder._get_nonce()
    assert resulting_field == expected_field
