# Contents of the logs directory.

All logs are *Bluetooth HCI snoop logs* taken on an Android phone 
running the *Nexxtmove* app to synchronize a Nexxternder Home charger over BLE.

All logs include Gatt table negotiation, 
so Wireshark should be able to assign handles to UUIDs and show them.

## hci_snoop20250507211007.cfa

The log contains a large amount Nexxtender messages, including:
- CHARGING_BASIC_DATA
- CHARGING_GRID_DATA
- CHARGING_CAR_DATA
- CHARGING_ADVANCED_DATA
- The following GENERIC_DATA:
    - Loader,  Time, Config
- CDR records
- CCDT records

## btsnoop_hci20241230_1.log
The log contains a large amount Nexxtender messages, including:
- CHARGING_BASIC_DATA
- CHARGING_GRID_DATA
- CHARGING_CAR_DATA
- CHARGING_ADVANCED_DATA
- The following GENERIC_DATA:
    - Time, Config

## btsnoop_hci20241230_2.log
The log contains a large amount Nexxtender messages, including:
- CHARGING_BASIC_DATA
- CHARGING_GRID_DATA
- CHARGING_CAR_DATA
- CHARGING_ADVANCED_DATA
- The following GENERIC_DATA:
    - Config


## btsnoop_hci_20141017_1.log
The log contains a large amount Nexxtender messages, including:
- CHARGING_BASIC_DATA
- CHARGING_GRID_DATA
- CHARGING_CAR_DATA
- CHARGING_ADVANCED_DATA

## hci_snoop20250125165300.cfa
The log contains a large amount Nexxtender messages, including:
- CHARGING_BASIC_DATA
- CHARGING_GRID_DATA
- CHARGING_CAR_DATA
- CHARGING_ADVANCED_DATA
- The following GENERIC_DATA:
    - Loader,  Time, Config
- CDR records
- CCDT records
