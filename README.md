# AgentTesla

This is a Zeek based AgentTesla malware detector.

### Testing PCAPs:

- https://app.any.run/tasks/f9421792-7d2c-47d3-90e0-07eb54ae12fa/
- https://app.any.run/tasks/db9f075c-7879-4957-923a-f79fac957a2d/#
- https://app.any.run/tasks/a30789ce-1e1c-4f96-a097-78c34b9fb612/

### Example:

```
$ zeek -Cr f9421792-7d2c-47d3-90e0-07eb54ae12fa.pcap zeek-agenttesla-detector

$ cat notice.log

#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2024-06-10-21-01-38
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1709838049.373142	CPhDKt12KQPUVbQz06	192.168.100.164	49210	143.95.79.226	44523	-	-	-	tcp	AgentTesla::C2_Traffic_Observed	Potential AgentTesla C2 over FTP data with payload in the sub field.	Time: 03/07/2024 19:00:36<br>User Name: admin<br>Computer Name: USER-PC<br>OSFullName: Microsoft Windows 7 Professional <br>CPU: Intel(R) Core(TM) i5-6400 CPU @ 2.70GHz<br>RAM: 3071.49 MB<br><hr>Host: https://m.facebook.com/<br>Username: honey@pot.com<br>Password: honeypass356<br>Application: Chrome<br><hr>Host: https://m.facebook.com<br>Username: honey@pot.com<br>Password: honeypass356<br>Application: Firefox<br><hr>Host: 1\x009\x002\x00.\x001\x006\x008\x00.\x001\x00.\x001<br>Username: honey@pot.com<br>Password: honeypass356<br>Application: Outlook<br><hr>	192.168.100.164	143.95.79.226	44523	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2024-06-10-21-01-38
```