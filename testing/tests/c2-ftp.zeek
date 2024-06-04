# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/f9421792-7d2c-47d3-90e0-07eb54ae12fa.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log
