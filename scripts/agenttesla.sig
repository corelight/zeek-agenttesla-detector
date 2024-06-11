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

signature agenttesla-http {
    ip-proto == tcp
    payload /^POST .*\x0d\x0a\x0d\x0ap=([A-Za-z0-9\/]|%2B){4}{75,}((([A-Za-z0-9\/]|%2B){3}=)|(([A-Za-z0-9\/]|%2B){2}==))?/
    eval AgentTesla::agenttesla_http_match    
}