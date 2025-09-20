module AgentTesla;

export {
	redef enum Notice::Type += {
		## This notice is generated when a connection is potentially Agent
		## Tesla malware C2.
		C2_Traffic_Observed
	};
}

# Common logging function
function logit(c: connection, over_what: string, data: string) 
	{
	local msg = fmt("Potential AgentTesla C2 %swith payload in the sub field.", over_what);

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=c]);
	}

# Signature match function for FTP
function agenttesla_ftp_match(state: signature_state, data: string): bool &is_used
	{
	logit(state$conn, "over FTP data ", data);

	return T;
	}

# Signature match function for SMTP/Generic
function agenttesla_match(state: signature_state, data: string): bool &is_used
	{
	logit(state$conn, "", data);

	return T;
	}

# Signature match function for HTTP
function agenttesla_http_match(state: signature_state, data: string): bool &is_used
	{
	logit(state$conn, "over HTTP ", data);

	return T;
	}