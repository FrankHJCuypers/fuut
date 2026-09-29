#! /bin/bash
#
# Example on how to use tshark to extract charging session data from a CDR pcap file for a specific time frame.
# Only charging sessions between $2 and $3 are output.
# Output is to stdout.
# Output format is CSV file with header names. It can be read with spreadsheet programs.
#
# Example:
# FilterCDRDateToCSV 2303-00005-E3_CDR_20260924202216.pcap 2026-09-01 2026-09-20
# 
# $1 CDR pcap file, example: 2303-00005-E3_CDR_20260924202216.pcap 
# $2 Filter start time. Used to filer on nexxtender.cdrr.sessionStartTime. 
#    Format: as shown in Wireshark for SessionStartTime. 
#    Example: 2026-09-01T12:17:42. Can be truncated from the right.
# $3 Filter end time. Used to filer on nexxtender.cdrr.sessionStartTime. 

# tshark outputs time fields as "2026-09-01T12:17:42.000000000+0200" (YYYY-MM-DDTHH:MM:SS.fffffffffZ) which is
# ISO 8601 extended format with nanosecond precision.
# I did not find how to change this.
# This format has 2 issues for importing in LibreOffice Calc:
# 1. A decimal symbol of "." is used, although I have it set to "," in Windows. 
#    LibreOffice follows the windows settings.
# 2. LibreOffice does not support the nanosecond precision or the time zone.
# So I use sed to strip the .fffffffffZ part from time fields.

tshark -r "$1" -o 'gui.column.format:"StartTime","%Yt","StartEnergy","%m","StopTime","%Cus:frame.time","StopEnergy","%m"' -t ud -T fields -E separator=, -E quote=d -E header=y -e nexxtender.cdrr.sessionStartTime -e nexxtender.cdrr.sessionStartEnergy -e nexxtender.cdrr.sessionStopTime -e nexxtender.cdrr.sessionStopEnergy -Y "nexxtender.cdrr.sessionStartTime > $2 and nexxtender.cdrr.sessionStartTime < $3" |
sed -e 's/\([[:digit:]][[:digit:]][[:digit:]][[:digit:]]-[[:digit:]][[:digit:]]-[[:digit:]][[:digit:]]T[[:digit:]][[:digit:]]:[[:digit:]][[:digit:]]:[[:digit:]][[:digit:]]\)\.0*[+-][[:digit:]]*/\1/g'
