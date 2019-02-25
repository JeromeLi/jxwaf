local ssl = require "ngx.ssl"
local waf = require "resty.jxwaf.waf"
local waf_rule = waf.get_waf_rule()
local host = ssl.server_name()
local ssl_host = waf_rule[host]
if ssl_host then
	local clear_ok, clear_err = ssl.clear_certs()
  if not clear_ok then
    local error_info = request.request['HTTP_FULL_INFO']()
    error_info['log_type'] = "error_log"
    error_info['error_type'] = "ssl"
    error_info['error_info'] = "failed to clear existing (fallback) certificates: "..clear_err
    ngx.ctx.error_log = error_info
    ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates: ",clear_err)
    return ngx.exit(400)
  end
	local pem_cert_chain = assert(ssl_host["domain_set"]["public_key"])
  local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
  if not der_cert_chain then
    local error_info = request.request['HTTP_FULL_INFO']()
    error_info['log_type'] = "error_log"
    error_info['error_type'] = "ssl"
    error_info['error_info'] = "failed to convert certificate chain ","from PEM to DER: "..err
    ngx.ctx.error_log = error_info
    ngx.log(ngx.ERR, "failed to convert certificate chain ","from PEM to DER: ", err)
    return ngx.exit(400)
  end
  local set_ok, set_err = ssl.set_der_cert(der_cert_chain)
  if not set_ok then
    local error_info = request.request['HTTP_FULL_INFO']()
    error_info['log_type'] = "error_log"
    error_info['error_type'] = "ssl"
    error_info['error_info'] = "failed to set DER cert: "..set_err
    ngx.ctx.error_log = error_info
    ngx.log(ngx.ERR, "failed to set DER cert: ", set_err)
    return ngx.exit(400)
  end
  local pem_pkey = assert(ssl_host["domain_set"]["private_key"])
  local der_pkey, der_err = ssl.priv_key_pem_to_der(pem_pkey)
  if not der_pkey then
    local error_info = request.request['HTTP_FULL_INFO']()
    error_info['log_type'] = "error_log"
    error_info['error_type'] = "ssl"
    error_info['error_info'] = "failed to convert private key ","from PEM to DER: "..der_err
    ngx.ctx.error_log = error_info
    ngx.log(ngx.ERR, "failed to convert private key ","from PEM to DER: ", der_err)
    return ngx.exit(400)
  end
  local set_key_ok, set_key_err = ssl.set_der_priv_key(der_pkey)
  if not set_key_ok then
    local error_info = request.request['HTTP_FULL_INFO']()
    error_info['log_type'] = "error_log"
    error_info['error_type'] = "ssl"
    error_info['error_info'] = "failed to set DER private key: "..set_key_err
    ngx.ctx.error_log = error_info
    ngx.log(ngx.ERR, "failed to set DER private key: ", set_key_err)
    return ngx.exit(400)
  end
else
	ngx.exit(403)
end
