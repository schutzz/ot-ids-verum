import os
from bacpypes.debugging import bacpypes_debugging, ModuleLogger
from bacpypes.core import run
from bacpypes.app import BIPSimpleApplication
from bacpypes.object import BinaryValueObject
from bacpypes.local.device import LocalDeviceObject

# Configuration
IP_ADDRESS = os.environ.get('BACNET_IP', '0.0.0.0/24')

# Setup device
this_device = LocalDeviceObject(
    objectName="AutomatedGate",
    objectIdentifier=599,
    maxApduLengthAccepted=1024,
    segmentationSupported="segmentedBoth",
    vendorIdentifier=15
)

# Create a custom Binary Value Object
class GateStateObject(BinaryValueObject):
    def __init__(self, **kwargs):
        super(GateStateObject, self).__init__(**kwargs)

# Setup Application
this_application = BIPSimpleApplication(this_device, IP_ADDRESS)

# Add Gate Object
gate_obj = GateStateObject(
    objectIdentifier=('binaryValue', 1),
    objectName='GateControl',
    presentValue='inactive', # active = Open, inactive = Closed
    description='Main Facility Gate'
)
this_application.add_object(gate_obj)

print(f"BACnet Gate Emulator running on {IP_ADDRESS}")
run()
