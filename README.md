[![maintainer](https://img.shields.io/badge/maintainer-Frank%20HJ%20Cuypers-green?style=for-the-badge&logo=github)](https://github.com/frankhjcuypers)
[![GitHub Discussions](https://img.shields.io/github/discussions/FrankHJCuypers/fuut?style=for-the-badge&logo=github)](https://github.com/FrankHJCuypers/fuut/discussions)
[![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/FrankHJCuypers/fuut?style=for-the-badge&logo=github)](https://github.com/FrankHJCuypers/fuut/issues)

[![Lua](https://img.shields.io/badge/Lua-2C2D72?style=for-the-badge&logo=lua)](https://www.lua.org/)
[![Static Badge](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark)](https://www.wireshark.org/)

[![experimental](https://img.shields.io/badge/version-experimental-red)](https://kotlinlang.org/docs/components-stability.html#stability-levels-explained)

[![GitHub Release](https://img.shields.io/github/v/release/FrankHJCuypers/fuut?include_prereleases&display_name=tag&logo=github)](https://github.com/FrankHJCuypers/fuut/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date-pre/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/releases)
[![GitHub License](https://img.shields.io/github/license/FrankHJCuypers/fuut?logo=github)](LICENSE)

[![GitHub last commit](https://img.shields.io/github/last-commit/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/commits)
[![GitHub contributors](https://img.shields.io/github/contributors/FrankHJCuypers/fuut?logo=github)](https://github.com/FrankHJCuypers/fuut/graphs/contributors)
[![GitHub commit activity (master)](https://img.shields.io/github/commit-activity/y/FrankHJCuypers/fuut/master?logo=github)](https://github.com/FrankHJCuypers/fuut/commits/master)


# Wireshark Dissector in Lua for Nexxtender charger BLE

The goal of this dissector is to dissect the Nexxtender specific BLE GATT messages that are exchanged
between the Nexxtmove app and the Nexxtender chargers,
according to 
[Nexxtender Charger Information](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information).
It was developed based on the [Gaai app project](https://frankhjcuypers.github.io/Gaai/).

For more information see [Analyzing Bluetooth Low Energy Traffic](https://github.com/FrankHJCuypers/Gaai/wiki/Analyzing-Bluetooth-Low-Energy-Traffic).

## Fuut?

Choosing a short distinctive name for a project is always difficult.
A bird name was chosen.
[Fuut](https://nl.wikipedia.org/wiki/Fuut) is Dutch for the
[Great crested grebe](https://en.wikipedia.org/wiki/Great_crested_grebe).

# Features

- Only requires [Wireshark](https://www.wireshark.org/)
- No build required.

# Installing 
Make sure that Wireshark is already installed.
Copy the `fuut.lua` file to one of Wireshark's lua script directories.
In Wireshark, open Help->About->Folders.
Any of the directories that includes *Lua scripts* in the *Typical files* directory will do.
I use the *Personal Lua Plugins* directory that expands to 
`C:\Users\Frank\AppData\Roaming\Wireshark\plugins` on my PC.

It is also recommended to configure The BLE names and characteristics as explained in 
[Wireshark: add Nexxtender Home BLE UUIDs](https://github.com/FrankHJCuypers/Gaai/wiki/Analyzing-Bluetooth-Low-Energy-Traffic#add-nexxtender-home-ble-uuids).

# Usage

The `fuut.lua` dissector parses all Wireshark BT ATT messages that are linked to the Nexxtender charger
and adds the parsed result to the Wireshark Packet Details view.

The following messages are already parsed by `fuut.lua`:

| Protocol           | Service  | Characteristic         | Type                    |
| ------------------ | -------- | ---------------------- | ----------------------- |
| NEXXTENDER_CBD     | CHARGING | CHARGING_BASIC_DATA    | NA                      |
| NEXXTENDER_CGD     | CHARGING | CHARGING_GRID_DATA     | NA                      |
| NEXXTENDER_CCD     | CHARGING | CHARGING_CAR_DATA      | NA                      |
| NEXXTENDER_CAD     | CHARGING | CHARGING_ADVANCED_DATA | NA                      |
| NEXXTENDER_GC      | GENERIC  | COMMAND                | NA                      |
| NEXXTENDER_GCL     | GENERIC  | COMMAND                | Loader                  |
| NEXXTENDER_GCE     | GENERIC  | COMMAND                | Event                   |
| NEXXTENDER_GCM     | GENERIC  | COMMAND                | Metric                  |
| NEXXTENDER_GCB     | GENERIC  | COMMAND                | Badge                   |
| NEXXTENDER_GCT     | GENERIC  | COMMAND                | Time                    |
| NEXXTENDER_GCC     | GENERIC  | COMMAND                | Config                  |
| NEXXTENDER_GS      | GENERIC  | STATUS                 | NA                      |
| NEXXTENDER_GSL     | GENERIC  | STATUS                 | Loader                  |
| NEXXTENDER_GSE     | GENERIC  | STATUS                 | Event                   |
| NEXXTENDER_GSM     | GENERIC  | STATUS                 | Metric                  |
| NEXXTENDER_GSB     | GENERIC  | STATUS                 | Badge                   |
| NEXXTENDER_GST     | GENERIC  | STATUS                 | Time                    |
| NEXXTENDER_GSC     | GENERIC  | STATUS                 | Config                  |
| NEXXTENDER_GD      | GENERIC  | DATA                   | NA                       |
| NEXXTENDER_GDL     | GENERIC  | DATA                   | Loader                  |
| NEXXTENDER_GDE     | GENERIC  | DATA                   | Event                   |
| NEXXTENDER_GDM     | GENERIC  | DATA                   | Metric                  |
| NEXXTENDER_GDB     | GENERIC  | DATA                   | Badge                   |
| NEXXTENDER_GDT     | GENERIC  | DATA                   | Time                    |
| NEXXTENDER_GDC1_0  | GENERIC  | DATA                   | Config                  |
| NEXXTENDER_GDC1_1  | GENERIC  | DATA                   | Config                  |
| NEXXTENDER_GDCCBOR | GENERIC  | DATA                   | Config                  |
| NEXXTENDER_CDRC    | CDR      | COMMAND                | NA                      |
| NEXXTENDER_CDRS    | CDR      | STATUS                 | NA                      |
| NEXXTENDER_CDRR    | CDR      | RECORD                 | NA                      |
| NEXXTENDER_CCDTC   | CCDT     | COMMAND                | NA                      |
| NEXXTENDER_CCDTS   | CCDT     | STATUS                 | NA                      |
| NEXXTENDER_CCDTR   | CCDT     | RECORD                 | NA                      |

The following messages are not yet parsed by `fuut.lua`:

| Protocol       | Service  | Characteristic         | Type        |
| -------------- | ---------| ---------------------- | ----------- |
| NEXXTENDER_FC  | FIRMWARE | COMMAND                | NA          |
| NEXXTENDER_FS  | FIRMWARE | STATUS                 | NA          |
| NEXXTENDER_FW  | FIRMWARE | WANTED_CHUNK           | NA          |
| NEXXTENDER_FD  | FIRMWARE | DATA_CHUNK             | NA          |

The type of message is shown in the *Protocol* column of the Wireshark Packet List view.

The values parsed by the `fuut.lua` dissector are shown in the Wireshark Packet Details view,
under the node *Bluetooth Attribute Protocol*, 
under the subnode that starts with *Nexxtender*.

For messages with a CRC, the CRC is verified and flagged as an error when wrong;
the CRC line will show red and a message is attached stating that the CRC is wrong, 
inlcuding the correct CRC.

For more information on the Nexxtender BLE protocol, see 
[Nexxtender Charger Information, Frank HJ Cuypers](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information).
The `fuut.lua` dissector uses the names and values from that document.

## Wireshark display filters

Wireshark [display filters](https://wiki.wireshark.org/DisplayFilters) can be used to only show specific packets.
Some examples:
- `_ws.col.protocol contains "NEXXTENDER_"`: only shows the NEXXTENDER_\* protocol messages
- `btatt.handle == 0x0022`: only shows ATT protocol messages for handle 0x22 (GENERIC/CDT: CCDT_COMMAND)
- `btatt.uuid128 == fd:47:41:6a:95:fb:42:06:88:b5:b4:a8:04:5f:75:c6`: only shows ATT protocol messages for the specific UUID (GENERIC/CDT: CCDT_COMMAND)
- `nexxtender.ccdtr`: only shows Nexxtender CCDT_RECORD messages.
- `nexxtender.ccdtr.l1 > 10`: only shows Nexxtender CCDT_RECORD messages with l1 > 10.

All field filter names that can be used in Wireshark are available in the Wireshark
menu item *option Analyze->Display Filter Expressions*.
Those relevant in the Nexxtender protocol stack are listed in the following table.

| Protocol name | Protocol description         | Field filter names |
| ------------- | ---------------------------- | ------------------ |
| Bluetooth     | Bluetooth                    | bluetooth.\*       |
| HCI_H4        | Bluetooth HCI H4             | hci_h4.\*          |
| HCI_ACL       | Bluetooth HCI ACL Packet     | bthci_acl.\*       |
| BT L2CAP      | Bluetooth L2CAP Protocol     | btl2cap.\*         |
| BT ATT        | Bluetooth Attribute Protocol | btatt.\*           |
| NEXXTENDER_\* | Nexttender \*                | nexxtender.\*.\*   |


The NEXXTENDER_\* level consists of the following "sub" protocols.
For each Nexxtender BLE characteristic, a new Wireshark protocol was defined.

| Protocol name      | Protocol description                 | Field filter names    |
| -------------------| ------------------------------------ | --------------------- |
| NEXXTENDER_CBD     | Nexxtender Charging Basic Data       | nexxtender.cbd.\*     |
| NEXXTENDER_CGD     | Nexxtender Charging Grid Data        | nexxtender.cgd.\*     |
| NEXXTENDER_CCD     | Nexxtender Charging Car Data         | nexxtender.ccd.\*     |
| NEXXTENDER_CAD     | Nexxtender Charging Advanced Data    | nexxtender.cad.\*     |
| NEXXTENDER_GC      | Nexxtender Generic Command           | NA                    |
| NEXXTENDER_GCL     | Nexxtender Generic Command: Loader   | nexxtender.gcl.\*     |
| NEXXTENDER_GCE     | Nexxtender Generic Command: Event    | nexxtender.gce.\*     |
| NEXXTENDER GCM     | Nexxtender Generic Command: Metrics  | nexxtender.gcm.\*     |
| NEXXTENDER_GCB     | Nexxtender Generic Command: Badge    | nexxtender.gcb.\*     |
| NEXXTENDER_GCT     | Nexxtender Generic Command: Time     | nexxtender.gct.\*     |
| NEXXTENDER_GCC     | Nexxtender Generic Command: Config   | nexxtender.gcc.\*     |
| NEXXTENDER_GS      | Nexxtender Generic Status            | nexxtender.NA         |
| NEXXTENDER_GSL     | Nexxtender Generic Status: Loader    | nexxtender.gsl.\*     |
| NEXXTENDER_GSE     | Nexxtender Generic Status: Event     | nexxtender.gse.\*     |
| NEXXTENDER_GSM     | Nexxtender Generic Status: Metrics   | nexxtender.gsm.\*     |
| NEXXTENDER_GSB     | Nexxtender Generic Status: Badge     | nexxtender.gsb.\*     |
| NEXXTENDER_GST     | Nexxtender Generic Status: Time      | nexxtender.gst.\*     |
| NEXXTENDER_GSC     | Nexxtender Generic Status: Config    | nexxtender.gsc.\*     |
| NEXXTENDER_GD      | Nexxtender Generic Data              | NA                    |
| NEXXTENDER_GDL     | Nexxtender Generic Data: Loader      | nexxtender.gdl.\*     |
| NEXXTENDER_GDE     | Nexxtender Generic Data: Event       | nexxtender.gde.\*     |
| NEXXTENDER_GDM     | Nexxtender Generic Data: Metrics     | nexxtender.gdm.\*     |
| NEXXTENDER_GDB     | Nexxtender Generic Data: Badge       | nexxtender.gdb.\*     |
| NEXXTENDER_GDT     | Nexxtender Generic Data: Time        | nexxtender.gdt.\*     |
| NEXXTENDER_GDC     | Nexxtender Generic Data: Config      | NA                    |
| NEXXTENDER_GDC1_0  | Nexxtender Generic Data: Config 1.0  | nexxtender.gdc1_0.\*  |
| NEXXTENDER_GDC1_1  | Nexxtender Generic Data: Config 1.1  | nexxtender.gdc1.1.\*  |
| NEXXTENDER_GDCCBOR | Nexxtender Generic Data: Config CBOR | nexxtender.gdcCBOR.\* |
| NEXXTENDER_CDRC    | Nexxtender CDR Command               | nexxtender.cdrc.\*    |
| NEXXTENDER_CDRS    | Nexxtender CDR Status                | nexxtender.cdrs.\*    |
| NEXXTENDER_CDRR    | Nexxtender CDR Record                | nexxtender.cdrr.\*    |
| NEXXTENDER_CCDTC   | Nexxtender CCDT Command              | nexxtender.ccdtc.\*   |
| NEXXTENDER_CCDTS   | Nexxtender CCDT Status               | nexxtender.ccdts.\*   |
| NEXXTENDER_CCDTR   | Nexxtender CCDT Record               | nexxtender.ccdtr.\*   |

The *Protocol name* is used as display value in the *Protocol* column of the Wireshark *packet list pane*
(_ws.col.protocol). 
When filtering on this column, the protocol name must be in upper case, like in 
`_ws.col.protocol contains "NEXXTENDER_`.

When filtering on the real protocol name of fields (so **not** via `_ws.col`),
the protocol name and fields must be in lower case, like in `nexxtender.ccdtr`.

# Internals

`fuut.lua` extends the Wireshark btgatt dissector 
[packet-btatt.c](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-btatt.c?ref_type=heads).
It adds dissectors to the *bluetooth.uid* table defined in *proto_reg_handoff_btgatt()*.



# Links

Useful information can be found at

- [Nexxtender Charger Information, Frank HJ Cuypers](https://github.com/FrankHJCuypers/Gaai/wiki/Nexxtender-Charger-Information)
- [Analyzing Bluetooth Low Energy Traffic](https://github.com/FrankHJCuypers/Gaai/wiki/Analyzing-Bluetooth-Low-Energy-Traffic)
- [Wireshark](https://www.wireshark.org/)
- [Creating a Wireshark dissector in Lua](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
- [Gaai app project](https://frankhjcuypers.github.io/Gaai/)
- [Gaai app github](https://github.com/FrankHJCuypers/Gaai)
# License

This project is licensed under the GNU AGPLv3 License. See the [LICENSE](LICENSE) file for details.



