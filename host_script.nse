author = 'update by cv'
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}


local http = require "http"
local json = require "json"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local stdnse = require "stdnse"

local api_version="1.2"
local mincvss=stdnse.get_script_args("vulners.mincvss")
mincvss = tonumber(mincvss) or 0.0

portrule = function(host, port)
  local vers=port.version
  return vers ~= nil and vers.version ~= nil
end

local cve_meta = {
  __tostring = function(me)
      return ("\t%s\t%s\thttps://vulners.com/%s/%s%s"):format(me.id, me.cvss or "", me.type, me.id, me.is_exploit and '\t*EXPLOIT*' or '')
  end,
}


function make_links(vulns)
  local output = {}

  if not vulns or not vulns.data or not vulns.data.search then
    return
  end

  for _, vuln in ipairs(vulns.data.search) do
    local v = {
      id = vuln._source.id,
      type = vuln._source.type,
      is_exploit = vuln._source.bulletinFamily:lower() == "exploit",
      cvss = tonumber(vuln._source.cvss.score),
    }

    if not v.cvss or (v.cvss == 0 and v.is_exploit) or mincvss <= v.cvss then
      setmetatable(v, cve_meta)
      output[#output+1] = v
    end
  end

  if #output > 0 then
    table.sort(output, function(a, b)
        return a.cvss > b.cvss or (a.cvss == b.cvss and a.id > b.id)
      end)
    return output
  end
end



function get_results(what, vers, type)
  local api_endpoint = "https://vulners.com/api/v3/burp/software/"
  local vulns
  local option={
    header={
      ['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version)
    },
    any_af = true,
  }

  local response = http.get_url(('%s?software=%s&version=%s&type=%s'):format(api_endpoint, what, vers, type), option)

  local status = response.status
  if status == nil then
    return
  elseif status ~= 200 then
    return
  end

  status, vulns = json.parse(response.body)

  if status == true then
    if vulns.result == "OK" then
      return make_links(vulns)
    end
  end
end

function get_vulns_by_software(software, version)
  return get_results(software, version, "software")
end

function get_vulns_by_cpe(cpe)
  local vers_regexp=":([%d%.%-%_]+)([^:]*)$"

  local _, _, vers = cpe:find(vers_regexp)

  if not vers then
    return
  end

  local output = get_results(cpe, vers, "cpe")

  if not output then
    local new_cpe

    new_cpe = cpe:gsub(vers_regexp, ":%1:%2")
    output = get_results(new_cpe, vers, "cpe")
  end

  return output
end

action = function(host, port)
  local tab = stdnse.output_table()
  local changed = false
  local response
  local output

  for i, cpe in ipairs(port.version.cpe) do
    output = get_vulns_by_cpe(cpe, port.version)
    if output then
      tab[cpe] = output
      changed = true
    end
  end

  if not changed then
    local vendor_version = port.version.product .. " " .. port.version.version
    output = get_vulns_by_software(port.version.product, port.version.version)
    if output then
      tab[vendor_version] = output
      changed = true
    end
  end

  if not changed then
    return
  end

  local output_str = stdnse.format_output(tab)
end