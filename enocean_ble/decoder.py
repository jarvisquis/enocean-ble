from enum import Enum

from Crypto.Cipher import AES
from home_assistant_bluetooth import BluetoothServiceInfo


class TelegramType(Enum):
    DATA = 0
    COMMISSION = 1


ALL_TELEGRAM_LENGTH_FIELD_SIZE: int = 1
ALL_TELEGRAM_TYPE_FIELD_SIZE: int = 1
ALL_TELEGRAM_MANUFACTURER_ID_SIZE: int = 2

DATA_TELEGRAM_SEQ_COUNTER_SIZE: int = 4
DATA_TELEGRAM_SWITCH_STATUS_SIZE: int = 1
DATA_TELEGRAM_SIGNATURE_SIZE: int = 4

ALL_TELEGRAM_TYPE_VALUE: bytes = b"\xFF"


class PTM215BDecoder:
    def __init__(self, raw_data: BluetoothServiceInfo) -> None:
        self.manufacturer_id = raw_data.manufacturer_id
        self.manufacturer_data = raw_data.manufacturer_data[raw_data.manufacturer_id]
        self.source_address = raw_data.address

        # Since we do not have the complete telegram at hand
        # we need to recontruct telegram total length to decide on telegram_type
        generic_field_bytes = (
            ALL_TELEGRAM_LENGTH_FIELD_SIZE
            + ALL_TELEGRAM_TYPE_FIELD_SIZE
            + ALL_TELEGRAM_MANUFACTURER_ID_SIZE
        )
        telegram_bytes_total = len(self.manufacturer_data) + generic_field_bytes

        if telegram_bytes_total == 30:
            self.telegram_type = TelegramType.COMMISSION
        else:
            self.telegram_type = TelegramType.DATA

    def is_signature_valid(self, sec_key: bytes) -> bool:
        if self.telegram_type == TelegramType.COMMISSION:
            raise ValueError("Signature check only possible for Data Telegrams.")

        # Calculate signature and verify against submitted signature
        cipher = AES.new(
            sec_key,
            AES.MODE_CCM,
            nonce=self._get_nonce(),
            mac_len=4,
            msg_len=0,
            assoc_len=len(self._input_data),
        )

        cipher.update(self._input_data)
        try:
            cipher.verify(self.signature)
        except ValueError:
            return False
        return True

    def _get_nonce(self) -> bytes:
        """Get Nonce of length 13 bytes consisting of source_address and seq counter and padding"""

        return self._source_address_le + self._seq_counter_le + b"\x00" * 3

    @property
    def _manufacturer_id_le(self) -> bytes:
        return self.manufacturer_id.to_bytes(
            ALL_TELEGRAM_MANUFACTURER_ID_SIZE, "little"
        )

    @property
    def _seq_counter_le(self) -> bytes:
        return self.manufacturer_data[:DATA_TELEGRAM_SEQ_COUNTER_SIZE]

    @property
    def _source_address_le(self) -> bytes:
        return bytes.fromhex("".join(self.source_address.split(":")[::-1]))

    @property
    def _input_data(self) -> bytes:
        """Rebuild complete data telegram payload using rebuilded length field, fixed value from type field and manufacturer data wo signature"""
        manufacturer_data_wo_signature = self.manufacturer_data[
            :-DATA_TELEGRAM_SIGNATURE_SIZE
        ]
        return (
            self._length_field
            + ALL_TELEGRAM_TYPE_VALUE
            + self._manufacturer_id_le
            + manufacturer_data_wo_signature
        )

    @property
    def _length_field(self) -> bytes:
        return (
            ALL_TELEGRAM_TYPE_FIELD_SIZE
            + ALL_TELEGRAM_MANUFACTURER_ID_SIZE
            + len(self.manufacturer_data)
        ).to_bytes(ALL_TELEGRAM_LENGTH_FIELD_SIZE, "big")

    @property
    def optional_data(self) -> bytes:
        # First sum up bytes count of mandatory fields
        non_optional_data_bytes = (
            DATA_TELEGRAM_SEQ_COUNTER_SIZE
            + DATA_TELEGRAM_SWITCH_STATUS_SIZE
            + DATA_TELEGRAM_SIGNATURE_SIZE
        )

        # If there are any other fields than the mandatory fields we expect them to be optional data
        optional_data_bytes = len(self.manufacturer_data) - non_optional_data_bytes
        if optional_data_bytes > 0:
            # In case we have optional data bytes we calculate starting index and extract data from list
            optional_data_start_index = (
                DATA_TELEGRAM_SEQ_COUNTER_SIZE + DATA_TELEGRAM_SWITCH_STATUS_SIZE
            ) - 1

            optional_data = self.manufacturer_data[
                optional_data_start_index : optional_data_start_index
                + optional_data_bytes
            ]

            # If there is only one byte we make sure it is not interpreted as int by python
            if isinstance(optional_data, int):
                optional_data = optional_data.to_bytes(optional_data_bytes, "big")
            return optional_data
        return b""

    @property
    def switch_status(self) -> bytes:
        status = self.manufacturer_data[DATA_TELEGRAM_SEQ_COUNTER_SIZE]
        if isinstance(status, int):
            return status.to_bytes(1, "big")
        return status

    @property
    def is_press_action(self) -> bool:
        return (self.switch_status[0] & 1) == 1

    @property
    def a0_action(self) -> bool:
        return ((self.switch_status[0] >> 1) & 1) == 1

    @property
    def a1_action(self) -> bool:
        return ((self.switch_status[0] >> 2) & 1) == 1

    @property
    def b0_action(self) -> bool:
        return ((self.switch_status[0] >> 3) & 1) == 1

    @property
    def b1_action(self) -> bool:
        return ((self.switch_status[0] >> 4) & 1) == 1

    @property
    def signature(self) -> bytes:
        signature_start_index = (
            len(self.manufacturer_data) - DATA_TELEGRAM_SIGNATURE_SIZE
        )
        return self.manufacturer_data[signature_start_index:]
