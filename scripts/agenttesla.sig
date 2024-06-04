signature agenttesla-ftp-data {
    ip-proto == tcp
    payload /^Time:.*<br>User Name:.*<br>Computer Name:.*/
    eval AgentTesla::agenttesla_ftp_match    
}

signature agenttesla-smtp {
    ip-proto == tcp
    payload /.+\x0d\x0a\x0d\x0aTime:.*<br>User Name:.*<br>Computer Name:.*/
    eval AgentTesla::agenttesla_smtp_match
}