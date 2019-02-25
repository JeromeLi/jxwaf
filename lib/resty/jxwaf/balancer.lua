local balancer = require "ngx.balancer"
local waf = require "resty.jxwaf.waf"
local waf_rule = waf.get_waf_rule()
local host = ngx.var.host
local balance_host = waf_rule[host]

if balance_host then
	local ip_lists = balance_host["domain_set"]["source_ip"]
	local port = balance_host["domain_set"]["source_http_port"]
	if not ngx.ctx.tries then
		ngx.ctx.tries = 0	
	end
	ngx.ctx.tries = ngx.ctx.tries + 1
	if not ngx.ctx.ip_lists then
		ngx.ctx.ip_lists = ip_lists
	end
	local ip_count = (string.sub(ngx.var.remote_addr,-1) % #ngx.ctx.ip_lists) + 1
	local _host = ngx.ctx.ip_lists[ip_count]
	local state_name,state_code = balancer.get_last_failure()
	if state_name == "failed" then
		for k,v in ipairs(ngx.ctx.ip_lists) do
        		if v == _host then
                		if not (#ngx.ctx.ip_lists == 1) then
                		table.remove(ngx.ctx.ip_lists,k)
                		ip_count = (string.sub(ngx.var.remote_addr,-1) % #ngx.ctx.ip_lists) + 1
                		_host = ngx.ctx.ip_lists[ip_count]
                		end
        		end
		end
	end
	local ok,err = balancer.set_current_peer(_host,port)
	if not ok then
        	ngx.log(ngx.ERR,"failed to set the current peer: ",err)
        	return ngx.exit(500)
	end
else
	ngx.exit(403)
end

