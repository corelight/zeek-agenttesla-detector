signature agenttesla-ftp-data {
    ip-proto == tcp
    payload /^Time:.*<br>User Name:.*<br>Computer Name:.*/
    eval AgentTesla::agenttesla_ftp_match    
}

signature agenttesla-generic {
    ip-proto == tcp
    payload /.+Time:.*<br>User Name:.*<br>Computer Name:.*/
    eval AgentTesla::agenttesla_match
}