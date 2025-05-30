Still to do.

+ Complete missing Nexxtender messages
+ Indent the Nexxtender messsage details one level up in the Wireshark Detail pane?
+ Handle messages that need chaining.
+ link Generic Data message with Generic Command message that requested it. Similar for others.
+ handle read command (not only its result), etc...
    + seems not possible at the BTATT level. The BTATT level has already parsed the complete command. There is no value any more to pass to the bluetooth.uuid level.
	It seems better to filter both on NEXXT_ and ATT
