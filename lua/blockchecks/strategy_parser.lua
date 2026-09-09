-- blockcheckS Mode A: whitelist parser for strategy.cmd (AUDIT §20, todo D4a)
--
-- The C-side execution plan is built from --lua-desync=... lines at startup
-- (execution_plan is a C struct — no dynamic insertion API). Mode A works
-- around that: Python publishes the FULL strategy line via strategy.cmd and
-- Lua builds plan-instance TABLES itself (plan_instance_execute only needs
-- {func, arg, payload_filter, range} — apply_execution_plan copies args,
-- plan_instance_execute_preapplied calls _G[instance.func]).
--
-- SECURITY: no load()/eval — family names and arg keys are whitelist-matched;
-- values are inert strings (arg values only ever reach string handlers).
-- Gen fence: the plan rebuilds only when the cmd text changes (cmd is
-- written atomically by Python via os.replace).

_G.bs_dyn_plan = _G.bs_dyn_plan or nil
_G.bs_dyn_cmd = _G.bs_dyn_cmd or nil
_G.bs_dyn_epoch = _G.bs_dyn_epoch or 0

-- Families callable as top-level desync functions (zapret-antidpi.lua).
local _FAMILIES = {
	fake = true,
	syndata = true,
	multisplit = true,
	multidisorder = true,
	multidisorder_legacy = true,
	hostfakesplit = true,
	fakedsplit = true,
	fakeddisorder = true,
	tcpseg = true,
	oob = true,
	wsize = true,
	wssize = true,
	rst = true,
	synack = true,
	synack_split = true,
	http_hostcase = true,
	http_domcase = true,
	http_methodeol = true,
	http_unixeol = true,
	udplen = true,
	dht_dn = true,
	pktmod = true,
}

-- Arg keys: SHAPE-only check (^([a-z0-9_]+)$). Values are inert strings —
-- they never execute; unknown keys are ignored by the desync functions
-- exactly like the C-side arg parser does (operator confs carry keys like
-- badsid/badseq beyond any fixed list). The REAL gate is the function
-- whitelist above — nothing outside zapret-antidpi families is callable.
local function _valid_key(k)
	return string.match(k, "^[a-z0-9_]+$") ~= nil
end

local function _safe_val(v)
	-- inert-string value shape; deliberately tight (no quotes/backslashes)
	if not v or #v == 0 or #v > 512 then return false end
	return string.match(v, "^[A-Za-z0-9_%-%+%.,/%%\\#=<>!~ ]+$") ~= nil
end

local _ALWAYS_RANGE = { from = { mode = "a", pos = 0 }, to = { mode = "a", pos = 0 }, upper_cutoff = false }

--- Parse ONE strategy line "family:opt=val:opt2=val2" → instance table or nil, err.
function bs_parse_strategy_line(line)
	line = string.gsub(line, "%s+$", "")
	if line == "" then return nil, "empty line" end
	local parts = {}
	for token in string.gmatch(line, "[^:]+") do
		table.insert(parts, token)
	end
	local family = parts[1]
	if not family or not _FAMILIES[family] then
		return nil, "family not whitelisted: " .. tostring(family)
	end
	local inst = {
		func = family,
		arg = {},
		payload_filter = "all",
		range = _ALWAYS_RANGE,
		func_n = 0,
		func_instance = "bs_dyn_" .. family,
	}
	for i = 2, #parts do
		local tok = parts[i]
		local k, v = string.match(tok, "^([a-z0-9_]+)=(.*)$")
		if k then
			if not _valid_key(k) then return nil, "arg key not whitelisted: " .. k end
			if not _safe_val(v) then return nil, "unsafe value for " .. k end
			inst.arg[k] = v
		else
			-- bare flag (badsum, nodrop, optional, nofake1, ...) — whitelist value-shape too
			if not _valid_key(tok) then return nil, "flag not whitelisted: " .. tok end
			inst.arg[tok] = "1"
		end
	end
	return inst
end

--- Parse a multi-line strategy.cmd body → fresh plan (array of instances).
function bs_parse_strategy_cmd(cmd_text)
	local plan = {}
	local lineno = 0
	for line in string.gmatch(cmd_text .. "\n", "([^\n]*)\n") do
		lineno = lineno + 1
		local trimmed = string.match(line, "^%s*(.-)%s*$")
		if trimmed ~= "" and string.sub(trimmed, 1, 1) ~= "#" then
			local inst, err = bs_parse_strategy_line(trimmed)
			if not inst then
				io.stderr:write(
					"blockcheckS: strategy_parser line "
						.. tostring(lineno)
						.. " rejected: "
						.. tostring(err)
						.. "\n"
				)
				io.stderr:flush()
				return nil
			end
			table.insert(plan, inst)
		end
	end
	if #plan == 0 then return nil end
	return plan
end

--- Fresh mutable copy per packet (plan_instance_pop removes entries).
function bs_copy_plan(src)
	local out = {}
	for i, inst in ipairs(src) do
		local argcopy = {}
		for k, v in pairs(inst.arg) do
			argcopy[k] = v
		end
		out[i] = {
			func = inst.func,
			arg = argcopy,
			payload_filter = inst.payload_filter,
			range = inst.range,
			func_n = inst.func_n,
			func_instance = inst.func_instance,
		}
	end
	return out
end

--- Poll strategy.cmd (Mode A): rebuild the dynamic plan when the text changes.
-- Returns true when a plan is available (Mode A active). After a rebuild the
-- PLAN_READY event with the published gen goes to events.ndjson — the Python
-- side fences the probe on it (the 50ms timer must not race the curl start).
function bs_poll_strategy_cmd()
	local path = writable_file_name("strategy.cmd")
	local f = io.open(path, "r")
	if not f then return false end
	local body = f:read("*a")
	f:close()
	body = string.gsub(body, "%s+$", "")
	if body == "" then return false end
	if body == _G.bs_dyn_cmd and _G.bs_dyn_plan then return true end
	local plan = bs_parse_strategy_cmd(body)
	if not plan then return false end
	_G.bs_dyn_cmd = body
	_G.bs_dyn_plan = plan
	_G.bs_dyn_epoch = _G.bs_dyn_epoch + 1
	local gen_path = writable_file_name("strategy.gen")
	local g = io.open(gen_path, "r")
	local gen = g and tonumber(g:read("*l")) or nil
	if g then g:close() end
	bs_write_ipc({ event = "PLAN_READY", gen = gen or 0 })
	return true
end
