import struct


class PTM215BDecoder:
    def __init__(self, raw_data: bytes) -> None:
        if len(raw_data) < 9:
            raise ValueError("Received data must be at least 9 bytes long")
        self.data = struct.unpack("<Ic4s", raw_data)

    @property
    def counter(self) -> int:
        return self.data[0]

    @property
    def is_press_action(self) -> bool:
        return (self.data[1] & 0b1) == 1

    @property
    def a0_action(self) -> bool:
        return ((self.data[1] >> 1) & 0b1) == 1

    @property
    def a1_action(self) -> bool:
        return ((self.data[1] >> 2) & 0b1) == 1

    @property
    def b0_action(self) -> bool:
        return ((self.data[1] >> 3) & 0b1) == 1

    @property
    def b1_action(self) -> bool:
        return ((self.data[1] >> 4) & 0b1) == 1
