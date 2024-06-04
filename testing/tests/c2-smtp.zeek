# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/db9f075c-7879-4957-923a-f79fac957a2d.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log
