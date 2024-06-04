module AgentTesla;

export {
	## The notice when AgentTesla C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed };
}

# Signature match function for FTP
function agenttesla_ftp_match(state: signature_state, data: string): bool &is_used
	{
	local id = state$conn$id;
	local msg = fmt("Potential AgentTesla C2 over FTP data between source %s and dest %s (is_orig=%s) with payload in the sub field.",
			id$orig_h, id$resp_h, state$is_orig);

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=state$conn]);

	return T;
	}

# Signature match function for SMTP/Generic/Not FTP
function agenttesla_match(state: signature_state, data: string): bool &is_used
	{
	local id = state$conn$id;
	local msg = fmt("Potential AgentTesla C2 between source %s and dest %s (is_orig=%s) with payload in the sub field.",
			id$orig_h, id$resp_h, state$is_orig);

	# Do not suppress notices.
	NOTICE([$note=AgentTesla::C2_Traffic_Observed, $msg=msg, $sub=data,
		$conn=state$conn]);

	return T;
	}
