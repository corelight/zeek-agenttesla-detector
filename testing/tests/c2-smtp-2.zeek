# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/a30789ce-1e1c-4f96-a097-78c34b9fb612.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log
