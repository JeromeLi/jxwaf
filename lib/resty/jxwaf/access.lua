local waf = require "resty.jxwaf.waf"

waf.access_init()
waf.custom_rule_check()
waf.geo_protection()
waf.limitreq_check()
waf.redirect_https()
waf.attack_ip_protection()
waf.owasp_rule_check()

