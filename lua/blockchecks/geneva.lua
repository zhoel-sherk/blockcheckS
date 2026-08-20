-- blockcheckS Geneva escape-hatch: custom fool= functions for TCP/IP field
-- manipulations that nfqws2 core cannot express (Geneva CCS'19 items 1-9,
-- 22, 24: TCP dataofs / options-wscale / IP total length / UTO, load corrupt).
--
-- Loaded only when BLOCKCHECKS_LUA_EXTRA contains "geneva.lua" (or staged via
-- --lua-init=@<path>). Each function registers a Geneva-style tamper:
--
--   --lua-desync=send:fool=bs_dataofs:badsum            # dup + dataofs:10 + chksum
--   --lua-desync=send:fool=bs_iplen:len=64              # dup + IP:len:replace:64
--   --lua-desync=send:fool=bs_corrupt_load              # dup + TCP:load:corrupt
--   --lua-desync=send:fool=bs_corrupt_wscale            # dup + TCP:options-wscale:corrupt
--   --lua-desync=send:fool=bs_corrupt_uto               # dup + TCP:options-uto:corrupt
--
-- fool= functions receive (dis, fooling_options) and must mutate `dis` in
-- place (apply_fooling runs before checksum recompute / rawsend).

-- TCP data offset: set to 10 (20-byte header) regardless of actual options.
function bs_dataofs(dis, fooling_options)
	if not dis.tcp then return end
	local ofs = tonumber(fooling_options["ofs"])
		or tonumber(fooling_options["bs_dataofs"])
		or 10
	-- th_off is 4 bits, *4 = header length in bytes
	dis.tcp.th_off = ofs
end

-- IP total length: set to N bytes (Geneva IP:len:replace).
function bs_iplen(dis, fooling_options)
	if not dis.ip then return end
	local len = tonumber(fooling_options["len"])
		or tonumber(fooling_options["bs_iplen"])
		or 64
	dis.ip.ip_len = len
end

-- Corrupt a single byte of the TCP payload (Geneva TCP:load:corrupt).
-- overwrites the first payload byte; if payload empty, falls back to seq bump.
function bs_corrupt_load(dis, fooling_options)
	if not dis.tcp then return end
	local off = tonumber(fooling_options["bs_corrupt_load"]) or 0
	local pl = dis.payload
	if pl and #pl > 0 and off < #pl then
		local b = pl:byte(off + 1)
		pl = pl:sub(1, off) .. string.char(b + 1) .. pl:sub(off + 2)
		dis.payload = pl
	end
end

-- Corrupt TCP option WScale (kind=3): set scale value to 0xFF.
function bs_corrupt_wscale(dis, fooling_options)
	if not dis.tcp or not dis.tcp.options then return end
	for _, opt in ipairs(dis.tcp.options) do
		if opt.kind == 3 then
			if opt.data then opt.data = string.char(0xff) end
			break
		end
	end
end

-- Corrupt TCP option UTO (kind=28, RFC 5482): set value to 0xFFFF.
function bs_corrupt_uto(dis, fooling_options)
	if not dis.tcp or not dis.tcp.options then return end
	for _, opt in ipairs(dis.tcp.options) do
		if opt.kind == 28 then
			if opt.data then opt.data = string.char(0xff, 0xff) end
			break
		end
	end
end
