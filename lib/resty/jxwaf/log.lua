local logger = require "resty.jxwaf.socket"
local cjson = require "cjson.safe"
local waf = require "resty.jxwaf.waf"
local uuid = require "resty.jxwaf.uuid"
local waf_rule = waf.get_waf_rule()
local host = ngx.var.host
local log_host = waf_rule[host]
local ngx_req_get_headers = ngx.req.get_headers

if log_host then
  if log_host['log_set']['log_remote'] == "true" then
    if not logger.initted() then
      local ok,err = logger.init{
        host = tonumber(log_host['log_set']['log_ip']),
        port = tonumber(log_host['log_set']['log_port']),
        sock_type = config_info.log_sock_type,
        flush_limit = 1,
        }
      if not ok then
        ngx.log(ngx.ERR,"failed to initialize the logger: ",err)
        return 
      end
    end
    local rule_log = ngx.ctx.rule_log
    if rule_log then
      rule_log['request_time'] = ngx.localtime()
      rule_log['uuid'] = uuid.generate_random()
      local bytes, err = logger.log(cjson.encode(rule_log))
      if err then
        ngx.log(ngx.ERR, "failed to log message: ", err)
      end
    end
    local error_log = ngx.ctx.error_log
    if error_log then
      error_log['request_time'] = ngx.localtime()
      error_log['uuid'] = uuid.generate_random()
      local bytes, err = logger.log(cjson.encode(error_log))
      if err then
        ngx.log(ngx.ERR, "failed to log message: ", err)
      end
    end
  end

  if log_host['log_set']['log_local'] == "true" then
    local rule_log = ngx.ctx.rule_log
    if rule_log then
      rule_log['request_time'] = ngx.localtime()
      rule_log['uuid'] = uuid.generate_random()
      ngx.log(ngx.ERR,cjson.encode(rule_log))
    end
  end
end
