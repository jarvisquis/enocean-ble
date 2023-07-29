import logging
from typing import Optional

from bluetooth_data_tools import short_address
from bluetooth_sensor_state_data import BluetoothData
from home_assistant_bluetooth import BluetoothServiceInfo
from sensor_state_data import BaseDeviceClass

from .decoder import PTM215BDecoder, TelegramType

logger = logging.getLogger(__name__)

MANUFACTURER_ID = 0x3DA

class EnoceanBinaryDeviceClass(BaseDeviceClass):
    # On means button pressed
    PRESSED = "pressed"


class EnoceanBluetoothDeviceData(BluetoothData):
    """Data for Enocean BLE Switch"""

    def __init__(
        self, security_key: Optional[str] = None, validate_signature: bool = False
    ) -> None:
        super().__init__()
        self._validate_signature = security_key is not None
        self._security_key = (
            bytes.fromhex(security_key) if self._validate_signature else None
        )

    def _start_update(self, data: BluetoothServiceInfo) -> None:
        if MANUFACTURER_ID not in data.manufacturer_data:
            logger.debug(f"Could not find manufacturer id {MANUFACTURER_ID} in data")
            return None

        decoder = PTM215BDecoder(data)
        if decoder.telegram_type != TelegramType.DATA:
            logger.debug("Only Update sensor for data telegrams")
            return None

        if self._validate_signature:
            if not decoder.is_signature_valid(self._security_key):
                logger.debug("Signature not valid.")
                return None
            logger.debug("Signature validated.")

        identifier = short_address(data.address)

        self.set_device_type("Enocean Switch")
        self.set_device_manufacturer(data.manufacturer)
        self.set_device_name(f"Enocean PTM215b {identifier}")

        self.update_binary_sensor(
            f"a0_pressed",
            decoder.a0_action and decoder.is_press_action,
            EnoceanBinaryDeviceClass.PRESSED,
            "Channel A0",
        )
        self.update_binary_sensor(
            "a1_pressed",
            decoder.a1_action and decoder.is_press_action,
            EnoceanBinaryDeviceClass.PRESSED,
            "Channel A1",
        )
        self.update_binary_sensor(
            "b0_pressed",
            decoder.b0_action and decoder.is_press_action,
            EnoceanBinaryDeviceClass.PRESSED,
            "Channel B0",
        )
        self.update_binary_sensor(
            "b1_pressed",
            decoder.b1_action and decoder.is_press_action,
            EnoceanBinaryDeviceClass.PRESSED,
            "Channel B1",
        )

    def commission(self, data: BluetoothServiceInfo) -> str:
        # TODO: Build logic to retrieve security key from device in commission mode
        ...
