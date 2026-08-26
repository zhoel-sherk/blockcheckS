-- blockcheckS IPC: append JSON lines to WRITABLE/events.ndjson

function bs_json_escape(s)
	if not s then return "" end
	s = tostring(s)
	s = string.gsub(s, "\\", "\\\\")
	s = string.gsub(s, '"', '\\"')
	s = string.gsub(s, "\n", "\\n")
	return s
end

_G.bs_ipc_open_fail = _G.bs_ipc_open_fail or 0

function bs_write_ipc(event_tbl)
	local path = writable_file_name("events.ndjson")
	local f = io.open(path, "a")
	if not f then
		_G.bs_ipc_open_fail = _G.bs_ipc_open_fail + 1
		io.stderr:write(
			"blockcheckS: bs_write_ipc open failed: "
				.. tostring(path)
				.. " (count="
				.. tostring(_G.bs_ipc_open_fail)
				.. ")\n"
		)
		io.stderr:flush()
		return
	end
	local parts = {}
	for k, v in pairs(event_tbl) do
		if type(v) == "number" then
			table.insert(parts, '"' .. k .. '":' .. tostring(v))
		elseif type(v) == "boolean" then
			table.insert(parts, '"' .. k .. '":' .. (v and "true" or "false"))
		else
			table.insert(parts, '"' .. k .. '":"' .. bs_json_escape(v) .. '"')
		end
	end
	f:write("{" .. table.concat(parts, ",") .. "}\n")
	f:close()
end

function bs_read_strategy_ipc()
	-- strategy.ready is the publish fence: Python replaces id/gen/cmd first,
	-- then ready last.  Reading ready before id/gen avoids split-read races.
	local ready_path = writable_file_name("strategy.ready")
	local ready_f = io.open(ready_path, "r")
	if not ready_f then return nil, nil end
	local ready_gen = tonumber(ready_f:read("*l"))
	ready_f:close()
	if not ready_gen then return nil, nil end

	local gen_path = writable_file_name("strategy.gen")
	local gen_f = io.open(gen_path, "r")
	if not gen_f then return nil, nil end
	local gen = tonumber(gen_f:read("*l"))
	gen_f:close()
	if gen ~= ready_gen then return nil, nil end

	local id_path = writable_file_name("strategy.id")
	local id_f = io.open(id_path, "r")
	if not id_f then return nil, nil end
	local id = tonumber(id_f:read("*l"))
	id_f:close()
	return id, gen
end

-- Daemon liveness heartbeat (epoch seconds). Python treats a stale file
-- (> ~2-3s with a 200ms period) as "daemon dead" BEFORE burning a probe
-- on queue-bypassed clean traffic.
function bs_write_heartbeat()
	local f = io.open(writable_file_name("heartbeat"), "w")
	if not f then return end
	f:write(tostring(os.time()))
	f:write("\n")
	f:close()
end
