import asyncio
import logging

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from .parser import BluetoothServiceInfo, PTM215BDecoder

logger = logging.getLogger(__name__)


def simple_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    if device.address.startswith("E2:15"):
        decoder = PTM215BDecoder(
            BluetoothServiceInfo.from_advertisement(device, advertisement_data, "")
        )
        print(device.address)
        print(
            "signature_valid: "
            + str(decoder.is_signature_valid(b'D\x18\xe4\x0c{{\x05na\xaa"\\C.\xa8\xad'))
        )
        print(f"a0: {decoder.a0_action}")
        print(f"b0: {decoder.b0_action}")
        print(f"a1: {decoder.a1_action}")
        print(f"b1: {decoder.b1_action}")
        print(f"is_press: {decoder.is_press_action}")


async def main():
    scanner = BleakScanner(simple_callback)

    while True:
        # print("(re)starting scanner")
        await scanner.start()
        await asyncio.sleep(2.0)
        await scanner.stop()


if __name__ == "__main__":
    asyncio.run(main())
