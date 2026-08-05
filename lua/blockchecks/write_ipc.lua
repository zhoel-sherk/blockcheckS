-- blockcheckS IPC: append JSON lines to WRITABLE/events.ndjson

function bs_json_escape(s)
	if not s then return "" end
	s = tostring(s)
	s = string.gsub(s, "\\", "\\\\")
	s = string.gsub(s, '"', '\\"')
	s = string.gsub(s, "\n", "\\n")
	return s
end

function bs_write_ipc(event_tbl)
	local path = writable_file_name("events.ndjson")
	local f = io.open(path, "a")
	if not f then return end
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
	local id_path = writable_file_name("strategy.id")
	local gen_path = writable_file_name("strategy.gen")
	local id_f = io.open(id_path, "r")
	if not id_f then return nil, nil end
	local id = tonumber(id_f:read("*l"))
	id_f:close()
	local gen_f = io.open(gen_path, "r")
	local gen = nil
	if gen_f then
		gen = tonumber(gen_f:read("*l"))
		gen_f:close()
	end
	return id, gen
end
