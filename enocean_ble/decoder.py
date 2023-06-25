import binascii
from enum import Enum

from Crypto.Cipher import AES
from home_assistant_bluetooth import BluetoothServiceInfo


class TelegramType(Enum):
    DATA = 0
    COMMISSION = 1


ALL_TELEGRAM_LENGTH_FIELD_BYTES: int = 1
ALL_TELEGRAM_TYPE_FIELD_BYTES: int = 1
ALL_TELEGRAM_MANUFACTURER_ID_BYTES: int = 2

DATA_TELEGRAM_SEQ_COUNTER_BYTES: int = 4
DATA_TELEGRAM_SWITCH_STATUS_BYTES: int = 1
DATA_TELEGRAM_SIGNATURE_BYTES: int = 4

ALL_TELEGRAM_TYPE_VALUE: bytes = b"\xFF"


class PTM215BDecoder:
    def __init__(self, data: BluetoothServiceInfo) -> None:
        self.manufacturer_id = data.manufacturer_id.to_bytes(
            ALL_TELEGRAM_MANUFACTURER_ID_BYTES, "little"
        )
        self.manufacturer_data = data.manufacturer_data[data.manufacturer_id]
        self.source_address = data.address

        # Since we do not have the complete telegram at hand
        # we need to recontruct telegram total length to decide on telegram_type
        generic_field_bytes = (
            ALL_TELEGRAM_LENGTH_FIELD_BYTES
            + ALL_TELEGRAM_TYPE_FIELD_BYTES
            + ALL_TELEGRAM_MANUFACTURER_ID_BYTES
        )
        telegram_bytes_total = len(self.manufacturer_data) + generic_field_bytes

        if telegram_bytes_total == 30:
            self.telegram_type = TelegramType.COMMISSION
        else:
            self.telegram_type = TelegramType.DATA

    def is_signature_valid(self, sec_key: bytes) -> bool:
        if self.telegram_type == TelegramType.COMMISSION:
            raise ValueError("Signature check only possible for Data Telegrams.")

        # Source needs to be in little endian order
        source_address_le = binascii.unhexlify(
            "".join(self.source_address.split(":")[::-1])
        )
        # Seq counter is provided as little endian in manufacturer data
        seq_counter_le = self.manufacturer_data[:DATA_TELEGRAM_SEQ_COUNTER_BYTES]

        # Since we do not have complete payload from telegram we need to rebuild length field
        length_field = self._create_length_field(
            ALL_TELEGRAM_LENGTH_FIELD_BYTES,
            ALL_TELEGRAM_TYPE_FIELD_BYTES,
            ALL_TELEGRAM_MANUFACTURER_ID_BYTES,
            len(self.manufacturer_data),
        )

        # Rebuild complete data telegram payload using rebuilded length field and adding fixed value von type field
        input_data = self._create_input_data(
            length_field,
            ALL_TELEGRAM_TYPE_VALUE,
            self.manufacturer_id,
            self.manufacturer_data[:-DATA_TELEGRAM_SIGNATURE_BYTES],
        )

        # Calculate signature and verify against submitted signature
        cipher = AES.new(
            sec_key,
            AES.MODE_CCM,
            nonce=self._create_nonce(source_address_le, seq_counter_le),
            mac_len=4,
            msg_len=0,
            assoc_len=len(input_data),
        )

        cipher.update(input_data)
        try:
            cipher.verify(self.signature)
        except ValueError:
            return False
        return True

    @staticmethod
    def _create_nonce(source_address_le: bytes, seq_counter_le: bytes) -> bytes:
        # Nonce has to be of length 13 bytes therefore padding of additional 3 zero bytes.
        # Other field values need to be little endian encoded
        return source_address_le + seq_counter_le + b"\x00" * 3

    @staticmethod
    def _create_input_data(
        length_field: bytes,
        type_field: bytes,
        manufacturer_id: bytes,
        manufacturer_data_wo_signature: bytes,
    ) -> bytes:
        return (
            length_field + type_field + manufacturer_id + manufacturer_data_wo_signature
        )

    @staticmethod
    def _create_length_field(
        length_field_size: int,
        type_field_size: int,
        manufacturer_id_size: int,
        manufacturer_data_size: int,
    ) -> bytes:
        return (
            type_field_size + manufacturer_id_size + manufacturer_data_size
        ).to_bytes(length_field_size, "big")

    @property
    def optional_data(self) -> bytes:
        # First sum up bytes count of mandatory fields
        non_optional_data_bytes = (
            DATA_TELEGRAM_SEQ_COUNTER_BYTES
            + DATA_TELEGRAM_SWITCH_STATUS_BYTES
            + DATA_TELEGRAM_SIGNATURE_BYTES
        )

        # If there are any other fields than the mandatory fields we expect them to be optional data
        optional_data_bytes = len(self.manufacturer_data) - non_optional_data_bytes
        if optional_data_bytes > 0:
            # In case we have optional data bytes we calculate starting index and extract data from list
            optional_data_start_index = (
                DATA_TELEGRAM_SEQ_COUNTER_BYTES + DATA_TELEGRAM_SWITCH_STATUS_BYTES
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
        status = self.manufacturer_data[DATA_TELEGRAM_SEQ_COUNTER_BYTES]
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
            len(self.manufacturer_data) - DATA_TELEGRAM_SIGNATURE_BYTES
        )
        return self.manufacturer_data[signature_start_index:]
