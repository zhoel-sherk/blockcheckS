-- blockcheckS scan_pick orchestrator + ClientHello / HTTP request poll

_G.bs_active_id = 1
_G.bs_active_gen = 0

local function bs_l7_ok(l7)
	return l7 == "tls_client_hello" or l7 == "http_req" or l7 == "quic_initial"
end

function bs_poll_strategy(ctx, desync)
	if not bs_l7_ok(desync.l7payload) then return end
	if not replay_first(desync) then return end
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
end

function scan_pick(ctx, desync)
	if not bs_l7_ok(desync.l7payload) then return end
	if not replay_first(desync) then return end
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
	orchestrate(ctx, desync)
	local id = tonumber(_G.bs_active_id) or 1
	local verdict = VERDICT_PASS
	local matched = 0
	while true do
		local inst = plan_instance_pop(desync)
		if not inst then break end
		local strat = tonumber(inst.arg.strategy)
		if strat and strat == id then
			verdict = plan_instance_execute(desync, verdict, inst)
			matched = matched + 1
		end
	end
	bs_write_ipc({
		event = "APPLIED",
		id = id,
		gen = tonumber(_G.bs_active_gen) or 0,
		matched = matched,
	})
	return verdict
end

function bs_timer_poll_strategy(name, data)
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
end

function smart_fallback(ctx, desync)
	-- Inbound RST detector (DPI fake RST with high TTL ≥ 64).
	-- Must run before bs_l7_ok: inbound RSTs carry no L7 payload.
	if not desync.outgoing
		and desync.dis.tcp
		and bit32.band(desync.dis.tcp.th_flags, 0x04) ~= 0
		and desync.dis.ip
	then
		local ttl = desync.dis.ip.ip_ttl
		if ttl and ttl >= 64 then
			bs_write_ipc({
				event = "STRATEGY_FAIL",
				reason = "rst_in",
				gen = tonumber(_G.bs_active_gen) or 0,
				ttl = ttl,
			})
		end
	end

	if not bs_l7_ok(desync.l7payload) then return end

	-- Outbound retransmission detector (DPI silent-drop)
	if desync.outgoing and is_retransmission(desync) then
		local state = desync.track.lua_state
		state.bs_retrans = (state.bs_retrans or 0) + 1
		if state.bs_retrans >= 2 and not state.bs_fail_sent then
			state.bs_fail_sent = true
			bs_write_ipc({
				event = "STRATEGY_FAIL",
				reason = "retrans",
				gen = tonumber(_G.bs_active_gen) or 0,
				ms = 0,
			})
		end
	end
end
