local cjson = require "cjson.safe"
local request = require "resty.jxwaf.request"
local transform = require "resty.jxwaf.transform"
local operator = require "resty.jxwaf.operator"
local resty_random = require "resty.random"
local pairs = pairs
local ipairs = ipairs
local table_insert = table.insert
local table_sort = table.sort
local table_concat = table.concat
local http = require "resty.jxwaf.http"
local upload = require "resty.upload"
local limitreq = require "resty.jxwaf.limitreq"
local geo = require 'resty.jxwaf.maxminddb'
local ngx_md5 = ngx.md5
local _M = {}
_M.version = "2.0"


local _config_path = "/opt/jxwaf/nginx/conf/jxwaf/jxwaf_config.json"
local _local_config_path = "/opt/jxwaf/nginx/conf/jxwaf/jxwaf_local_config.json"
local _config_geo_path = "/opt/jxwaf/nginx/conf/jxwaf/GeoLite2-Country.mmdb"
local _update_waf_rule = {}
local _config_info = {}
local _auto_update = "true"
local _auto_update_period = "300"


local function _process_request(var)
	local t = request.request[var.rule_var]()
	if type(t) ~= "string" and type(t) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not decode http args ",type(t).."   "..var.rule_var)
		ngx.log(ngx.ERR,ngx.req.raw_header())
		ngx.exit(500)
	end
	if type(t) == "string" then
		return t
	end
	
	local rule_var = var.rule_var
	if (rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "ARGS_HEADERS" or rule_var == "ARGS_COOKIES" ) then
		if( type(var.rule_specific) == "table" ) then
			local specific_result = {}
			for _,v in ipairs(var.rule_specific) do
				local specific = t[v]
				if specific ~= nil then
					specific_result[v] = specific
				end
			end
			return specific_result
		end
    
		if( type(var.rule_ignore) == "table" ) then
			local ignore_result = {}
			ignore_result = t
			for _,v in ipairs(var.rule_ignore) do
				ignore_result[string.lower(v)] = nil
			end
			return ignore_result
		end				
	end
	
	return t
end



function _M.process_request(var)
	return _process_request(var)
end



local function _process_transform(process_request,rule_transform,var)
  if type(process_request) ~= "string" and type(process_request) ~= "table" then
    ngx.log(ngx.ERR,"run fail,can not transfrom http args")
    ngx.exit(500)
  end

	if  type(rule_transform) ~= "table" then
    ngx.log(ngx.ERR,"run fail,can not decode config file,transfrom error")
    ngx.exit(500)
  end

	if type(process_request) == "string" then
		local string_result = process_request
		for _,v in ipairs(rule_transform) do
			string_result = transform.request[v](string_result)				
		end
		return 	string_result
	end

	local result = {}
	local rule_var = var.rule_var
	if (rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "ARGS_HEADERS" or rule_var == "ARGS_COOKIES" ) then
		for k,v in pairs(process_request) do
      if type(v) == "table" then
      local _result_table = {}
      for _,_v in ipairs(v) do
        local _result = _v
        for _,__v in ipairs(rule_transform) do
          _result = transform.request[__v](_result)
        end 
        if type(_result) == "string" then
          table_insert(_result_table,_result)
        end
      end
      result[k] = _result_table
      else
        local _result = v
        for _,_v in ipairs(rule_transform) do
          _result = transform.request[_v](_result)
        end
        if type(_result) == "string" then
          result[k] = _result
        end
      end
    end
	else
		for _,v in ipairs(process_request) do
			local _result = v
			for _,_v in ipairs(rule_transform) do
				_result = transform.request[_v](_result)
			end
			if type(_result) == "string" then
				table_insert(result,_result)
			end
		end
	end
	return result 
end


local function _process_operator( process_transform , match , var , rule )
	local rule_operator = match.rule_operator
	local rule_pattern = match.rule_pattern
	local rule_var = var.rule_var
	if type(process_transform) ~= "string" and type(process_transform) ~= "table" then
		ngx.log(ngx.ERR,"run fail,can not operator http args")
    ngx.exit(500)
  end
	if type(rule_operator) ~= "string" and type(rule_pattern) ~= "string" then
		ngx.log(ngx.ERR,"rule_operator and rule_pattern error")
		ngx.exit(500)
	end
	
	if type(process_transform) == "string" then
		local result ,value
		result,value = operator.request[rule_operator](process_transform,rule_pattern)
		if result  then
			return result,value,rule_var
		else
			return result
		end
	end

	if (rule_var == "ARGS_GET" or rule_var == "ARGS_POST" or rule_var == "ARGS_HEADERS" or rule_var == "ARGS_COOKIES" ) then
		for k,v in pairs(process_transform) do
			if type(v) == "table" then
				for _,_v in ipairs(v) do
					local result,value
					result,value = operator.request[rule_operator](_v,rule_pattern)	
					if result  then
						return result,value,k
					end
				end
			else
				local result,value
				result,value = operator.request[rule_operator](v,rule_pattern) 
        if result  then
          return result,value,k
        end
			end
		end	
	else
		for _,v in ipairs(process_transform) do
			local result,value
			result,value = operator.request[rule_operator](v,rule_pattern)
			if result  then
				return result,value,rule_var
			end
		end
	end
	return false
end

local function _update_at(auto_update_period,global_update_rule)
    if _auto_update == "true" then
      local global_ok, global_err = ngx.timer.at(tonumber(auto_update_period),global_update_rule)
      if not global_ok then
        ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
      end
    end
end

local function _global_update_rule()
    local _update_website  =  _config_info.waf_update_website or "http://update2.jxwaf.com/waf_update"
    local httpc = http.new()
    local api_key = _config_info.waf_api_key or ""
    local api_password = _config_info.waf_api_password or ""
    local res, err = httpc:request_uri( _update_website , {
	
        method = "POST",
        body = "api_key="..api_key.."&api_password="..api_password,
        headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        }
    })
    if not res then
      ngx.log(ngx.ERR,"failed to request: ", err)
      return _update_at(tonumber(_auto_update_period),_global_update_rule)
    end
		local res_body = cjson.decode(res.body)
		if not res_body then
      ngx.log(ngx.ERR,"init fail,failed to decode resp body " )
      return _update_at(tonumber(_auto_update_period),_global_update_rule)
		end
    if  res_body['result'] == false then
      ngx.log(ngx.ERR,"init fail,failed to request, ",res_body['message'])
      return _update_at(tonumber(_auto_update_period),_global_update_rule)
    end
    _update_waf_rule = res_body['waf_rule']
    if _update_waf_rule == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf rule")
      return _update_at(tonumber(_auto_update_period),_global_update_rule)
    end
    _auto_update = res_body['auto_update']
    _auto_update_period = res_body['auto_update_period']
    if _auto_update == "true" then
      local global_ok, global_err = ngx.timer.at(tonumber(_auto_update_period),_global_update_rule)
      if not global_ok then
        ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
      end
    end
    ngx.log(ngx.ERR,cjson.encode(res_body))
end



function _M.init_worker()
	if _config_info.waf_local == "false" then
    local init_ok,init_err = ngx.timer.at(0,_global_update_rule)
    if not init_ok then
      ngx.log(ngx.ERR, "failed to create the init timer: ", init_err)
    end
  end
end

function _M.init(config_path)
  require "resty.core"
	local init_config_path = config_path or _config_path
	local read_config = assert(io.open(init_config_path,'r'))
	local raw_config_info = read_config:read('*all')
	read_config:close()
	local config_info = cjson.decode(raw_config_info)
	if config_info == nil then
		ngx.log(ngx.ERR,"init fail,can not decode config file")
	end
	_config_info = config_info
	if _config_info.waf_local == "true" then
		local init_local_config_path =  _local_config_path
		local read_local_config = assert(io.open(init_local_config_path,'r'))
		local raw_local_config_info = read_local_config:read('*all')
		read_local_config:close()
		local res_body = cjson.decode(raw_local_config_info)
    _update_waf_rule = res_body['waf_rule']
    if _update_waf_rule == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf rule")
    end
  end
  if not geo.initted() then
    local r,errs = geo.init(_config_geo_path)
    if errs then
      ngx.log(ngx.ERR,errs)
    end
		ngx.log(ngx.ERR,"init geoip success")
  end
  if not geo.initted() then
    ngx.log(ngx.ERR,"init geoip fail")
  end
end


function _M.get_waf_rule()
	
	local update_waf_rule = _update_waf_rule

	return update_waf_rule

end

local function _custom_rule_match(rules)
	local result
	for _,rule in ipairs(rules) do
    local matchs_result = true
    local ctx_rule_log = {}
    for _,match in ipairs(rule.rule_matchs) do
      local operator_result = false
      for _,var in ipairs(match.rule_vars) do
        local process_request = _process_request(var)
        local process_transform = _process_transform(process_request,match.rule_transform,var)
        local _operator_result,_operator_value,_operator_key = _process_operator(process_transform,match,var,rule)
        if _operator_result and rule.rule_log == "true" then
          ctx_rule_log.rule_var = var.rule_var
          ctx_rule_log.rule_operator = match.rule_operator
          ctx_rule_log.rule_transform = match.rule_transform
					ctx_rule_log.rule_match_var = _operator_value
          ctx_rule_log.rule_match_key = _operator_key
          ctx_rule_log.rule_pattern = match.rule_pattern
        end
        if  _operator_result then
          operator_result = _operator_result
          break
        end
      end	
      if (not operator_result) then
        matchs_result = false
        break
      end
    end
    if matchs_result and rule.rule_log == "true" then                       
      local rule_log = request.request['HTTP_FULL_INFO']()
      rule_log['log_type'] = "protection_log"
      rule_log['protection_type'] = "custom_rule"
      rule_log['protection_info'] = "custom_rule_info"
      rule_log['rule_id'] = rule.rule_id
      rule_log['rule_name'] = rule.rule_name
      rule_log['rule_level'] = rule.rule_level
      rule_log['rule_action'] = rule.rule_action
      rule_log['rule_var'] = ctx_rule_log.rule_var
      rule_log['rule_operator'] = ctx_rule_log.rule_operator
      rule_log['rule_transform'] = ctx_rule_log.rule_transform
      rule_log['rule_pattern'] = ctx_rule_log.rule_pattern
      rule_log['rule_match_var'] = ctx_rule_log.rule_match_var
      rule_log['rule_match_key'] = ctx_rule_log.rule_match_ke
      ngx.ctx.rule_log = rule_log
    end
    if rule.rule_action == "pass" and matchs_result then
      matchs_result = false
    end
    if matchs_result then
      return matchs_result,rule
    end
	end
	return result
end

function _M.custom_rule_check()
	local host = ngx.var.host
  local scheme = ngx.var.scheme
  local req_host = _update_waf_rule[host]
	if req_host and req_host['domain_set'][scheme] == "true" then
		if req_host["protection_set"]["custom_protection"] == "true"  and #req_host["custom_rule_set"]  ~= 0 then
      local result,match_rule = _custom_rule_match(req_host["custom_rule_set"])
      if result then
        if match_rule.rule_action == 'deny' then
          ngx.exit(403)
        elseif match_rule.rule_action == 'allow' then
          ngx.exit(0)
        end
      end
		end
	else
    ngx.exit(403)
	end
  
end


function _M.geo_protection()
  local host = ngx.var.host
  local req_host = _update_waf_rule[host]
	if req_host and req_host["protection_set"]["geo_protection"] == "true" then
		local res,err = geo.lookup(ngx.var.remote_addr)
		if res then
			if res.country.names.en ~= "China" then
        local rule_log = request.request['HTTP_FULL_INFO']()
        rule_log['log_type'] = "protection_log"
        rule_log['protection_type'] = "geo_protection"
        rule_log['protection_info'] = "geo_protection_info"
        rule_log['country'] = res.country.names.en
        ngx.ctx.rule_log = rule_log
				ngx.exit(400)
			end
		end
	end
end

function _M.redirect_https()
  local scheme = ngx.var.scheme
  if scheme == "https" then
    return
  end
  local host = ngx.var.host
  local req_host = _update_waf_rule[host]
	if req_host and  req_host['domain_set']['redirect_https'] == "true"  then
    ngx.header.content_type = "text/html"
    ngx.say([=[ <script type="text/javascript">
      var targetProtocol = "https:";
      if (window.location.protocol != targetProtocol)
      window.location.href = targetProtocol +
      window.location.href.substring(window.location.protocol.length);
      </script>
      ]=] )
  end
end



function _M.limitreq_check()
  local host = ngx.var.host
  local req_host = _update_waf_rule[host]
	if req_host and req_host["protection_set"]["cc_protection"] == "true"  then
			local req_rate_rule = {}
			local req_count_rule = {}
			local req_domain_rule = {}
			req_count_rule['rule_rate_count'] = req_host['cc_protection_set']['count']
			req_count_rule['rule_burst_time'] = req_host['cc_protection_set']['black_ip_time']
			req_rate_rule['rule_rate_count'] = req_host['cc_protection_set']['ip_qps']
			req_rate_rule['rule_burst_time'] = req_host['cc_protection_set']['ip_expire_qps']
			req_domain_rule['domain_qps'] = req_host['cc_protection_set']['domain_qps']
			req_domain_rule['attack_count'] = req_host['cc_protection_set']['attack_count'] 
			req_domain_rule['attack_black_ip_time'] = req_host['cc_protection_set']['attack_black_ip_time']
			req_domain_rule['attack_ip_qps'] = req_host['cc_protection_set']['attack_ip_qps']
			req_domain_rule['attack_ip_expire_qps'] = req_host['cc_protection_set']['attack_ip_expire_qps']
			limitreq.limit_req_count(req_count_rule,ngx_md5(ngx.var.remote_addr))
      limitreq.limit_req_rate(req_rate_rule,ngx_md5(ngx.var.remote_addr))
			limitreq.limit_req_domain_rate(req_domain_rule,ngx_md5(host))
	end
	
end

function _M.attack_ip_protection()
  local host = ngx.var.host
  local req_host = _update_waf_rule[host]
	if req_host and req_host["protection_set"]["attack_ip_protection"] == "true"  then
			local req_count_rule = {}
			req_count_rule['rule_rate_count'] = req_host['protection_set']['attack_ip_protection_count']
			req_count_rule['rule_burst_time'] = req_host['protection_set']['attack_ip_protection_time']
			limitreq.limit_attack_ip(req_count_rule,ngx_md5(ngx.var.remote_addr),false)
	end
end




local function _owasp_rule_match(rules)
	local result
	for _,rule in ipairs(rules) do
    local matchs_result = true
    local ctx_rule_log = {}
    for _,match in ipairs(rule.rule_matchs) do
      local operator_result = false
      for _,var in ipairs(match.rule_vars) do
        local process_request = _process_request(var)
        local process_transform = _process_transform(process_request,match.rule_transform,var)
        local _operator_result,_operator_value,_operator_key = _process_operator(process_transform,match,var,rule)
        if _operator_result and rule.rule_log == "true" then
          ctx_rule_log.rule_var = var.rule_var
          ctx_rule_log.rule_operator = match.rule_operator
          ctx_rule_log.rule_transform = match.rule_transform
					ctx_rule_log.rule_match_var = _operator_value
          ctx_rule_log.rule_match_key = _operator_key
          ctx_rule_log.rule_pattern = match.rule_pattern
        end
        if  _operator_result then
          operator_result = _operator_result
          break
        end
      end	
      if (not operator_result) then
        matchs_result = false
        break
      end
    end
    if matchs_result and rule.rule_log == "true" then                       
      local rule_log = request.request['HTTP_FULL_INFO']()
      rule_log['log_type'] = "protection_log"
      rule_log['protection_type'] = "owasp_rule"
      rule_log['protection_info'] = "owasp_rule_info"
      rule_log['rule_id'] = rule.rule_id
      rule_log['rule_name'] = rule.rule_name
      rule_log['rule_level'] = rule.rule_level
      rule_log['rule_action'] = rule.rule_action
      rule_log['rule_var'] = ctx_rule_log.rule_var
      rule_log['rule_operator'] = ctx_rule_log.rule_operator
      rule_log['rule_transform'] = ctx_rule_log.rule_transform
      rule_log['rule_pattern'] = ctx_rule_log.rule_pattern
      rule_log['rule_match_var'] = ctx_rule_log.rule_match_var
      rule_log['rule_match_key'] = ctx_rule_log.rule_match_ke
      ngx.ctx.rule_log = rule_log
    end
    if rule.rule_action == "pass" and matchs_result then
      matchs_result = false
    end
    if matchs_result then
      return matchs_result,rule
    end
	end
	return result
end

function _M.owasp_rule_check()
	local host = ngx.var.host
  local req_host = _update_waf_rule[host]
	if req_host and req_host['protection_set']['owasp_protection'] == "true" and #req_host["owasp_rule_set"] ~= 0 then
    local result,match_rule = _owasp_rule_match(req_host["owasp_rule_set"])
    if result then
      if match_rule.rule_action == 'deny' then
        if req_host["protection_set"]["attack_ip_protection"] == "true"  then
          local req_count_rule = {}
          req_count_rule['rule_rate_count'] = req_host['protection_set']['attack_ip_protection_count']
          req_count_rule['rule_burst_time'] = req_host['protection_set']['attack_ip_protection_time']
          limitreq.limit_attack_ip(req_count_rule,ngx_md5(ngx.var.remote_addr),true)
        end
        ngx.exit(403)
      elseif match_rule.rule_action == 'allow' then
        ngx.exit(0)
      end
    end
	end
end



function _M.access_init()
	local content_type = ngx.req.get_headers()["Content-type"]
	if content_type and  ngx.re.find(content_type, [=[^multipart/form-data]=],"oij") and tonumber(ngx.req.get_headers()["Content-Length"]) ~= 0 then
		local form, err = upload:new()
		local _file_name = {}
		local _form_name = {}
		local _file_type = {}
		local t ={}
		local _type_flag = "false"
		if not form then
			ngx.log(ngx.ERR, "failed to new upload: ", err)
			ngx.exit(500)	
		end
		ngx.req.init_body()
		ngx.req.append_body("--" .. form.boundary)
		local lasttype, chunk
		local count = 0
		while true do
			count = count + 1
			local typ, res, err = form:read()
                if not typ then
                    ngx.say("failed to read: ", err)
                	return nil
                end
				if typ == "header" then
				--	chunk = res[3]
				--	ngx.req.append_body("\r\n" .. chunk)
                    if res[1] == "Content-Disposition" then
                    	local _tmp_form_name = ngx.re.match(res[2],[=[(.+)\bname=[" ']*?([^"]+)[" ']*?]=],"oij")
						local _tmp_file_name =  ngx.re.match(res[2],[=[(.+)filename=[" ']*?([^"]+)[" ']*?]=],"oij")
                    	if _tmp_form_name  then
                        	table.insert(_form_name,_tmp_form_name[2]..count)
						end
						if _tmp_file_name  then
							table.insert(_file_name,_tmp_file_name[2])
						end
						if _tmp_form_name and _tmp_file_name then
							chunk = string.format([=[Content-Disposition: form-data; name="%s"; filename="%s"]=],_tmp_form_name[2],_tmp_file_name[2])
							ngx.req.append_body("\r\n" .. chunk)
						elseif _tmp_form_name then
							chunk = string.format([=[Content-Disposition: form-data; name="%s"]=],_tmp_form_name[2])
							 ngx.req.append_body("\r\n" .. chunk)
						else
							ngx.log(ngx.ERR,"Content-Disposition ERR!")
							ngx.exit(503)
						end

                	end
                	if res[1] == "Content-Type" then
                    	table.insert(_file_type,res[2])
						_type_flag = "true"
						chunk = string.format([=[Content-Type: %s]=],res[2])
						ngx.req.append_body("\r\n" .. chunk)
                	end
            	end
				if typ == "body" then
					chunk = res
					if lasttype == "header" then
						ngx.req.append_body("\r\n\r\n")
					end
					ngx.req.append_body(chunk)
                    if _type_flag == "true" then
                        _type_flag = "false"
						t[_form_name[#_form_name]] = ""
					else
						if lasttype == "header" then
							t[_form_name[#_form_name]] = res
						else
							t[_form_name[#_form_name]] = ""
						end
                    end
				end
				if typ == "part_end" then 
					ngx.req.append_body("\r\n--" .. form.boundary)
				end
				if typ == "eof" then
					ngx.req.append_body("--\r\n")
                    break
				end
				lasttype = typ
		end
		form:read()
		ngx.req.finish_body()
		ngx.ctx.form_post_args = t
		ngx.ctx.form_file_name = _file_name
		ngx.ctx.form_file_type = _file_type
	else
		ngx.req.read_body()
	end
end

function _M.resp_header_chunk()
	return _resp_header_chunk
end

return _M
