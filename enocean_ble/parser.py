import logging

from bluetooth_data_tools import short_address
from bluetooth_sensor_state_data import BluetoothData
from home_assistant_bluetooth import BluetoothServiceInfo

from .decoder import PTM215BDecoder

logger = logging.getLogger(__name__)

MANUFACTURER_ID = 0x3DA


class EnoceanBluetoothDeviceData(BluetoothData):
    """Data for Enocean BLE Switch"""

    def _start_update(self, data: BluetoothServiceInfo) -> None:
        try:
            raw_data = data.manufacturer_data[MANUFACTURER_ID]
        except (KeyError, IndexError):
            logger.debug(f"Could not find manufacturer id {MANUFACTURER_ID} in data")
            return None

        decoder = PTM215BDecoder(raw_data)

        # TODO:besseren identifier überlegen
        identifier = short_address(data.address)

        self.set_device_type("Enocean Switch")
        self.set_device_manufacturer("Enocean GmbH")
        self.set_device_name(f"Enocean {identifier}")

        # TODO: Update sensor