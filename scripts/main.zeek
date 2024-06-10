module AgentTesla;

export {
	## The notice when AgentTesla C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed };
}

# Signature match function for FTP
function agenttesla_ftp_match(state: signature_state, data: string): bool &is_used
	{
	local id = state$conn$id;
	local msg = "Potential AgentTesla C2 over FTP data with payload in the sub field.";

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=state$conn]);

	return T;
	}

# Signature match function for SMTP/Generic
function agenttesla_match(state: signature_state, data: string): bool &is_used
	{
	local id = state$conn$id;
	local msg = "Potential AgentTesla C2 with payload in the sub field.";

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=state$conn]);

	return T;
	}

# Signature match function for HTTP
function agenttesla_http_match(state: signature_state, data: string): bool &is_used
	{
	local id = state$conn$id;
	local msg = "Potential AgentTesla C2 over HTTP with payload in the sub field.";

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=state$conn]);

	return T;
	}