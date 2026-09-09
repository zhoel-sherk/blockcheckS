-- blockcheckS scan_pick orchestrator + ClientHello / HTTP request poll
-- Mode A (AUDIT §20): strategy.cmd drives a dynamic whitelist-parsed plan;
-- Mode B (default): the conf carries strategy=N instances, id published via shm.

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

	-- Mode A: the conf carries no strategy=N instances; the FULL strategy
	-- line arrives via strategy.cmd and is parsed by the 200ms timer into
	-- _G.bs_dyn_plan (no per-packet io — packets flow continuously). Falls
	-- back to the Mode B conf-plan path when no cmd has ever been published.
	if _G.bs_dyn_plan then
		desync.plan = bs_copy_plan(_G.bs_dyn_plan)
		orchestrate_apply_dynamic(ctx, desync)
		return bs_finish_pick(desync, id)
	end

	orchestrate(ctx, desync)
	return bs_finish_pick(desync, id)
end

-- Shared tail: execute the plan instances and write APPLIED (matched != 0).
function bs_finish_pick(desync, id)
	local verdict = VERDICT_PASS
	local matched = 0
	while true do
		local inst = plan_instance_pop(desync)
		if not inst then break end
		local strat = tonumber(inst.arg.strategy)
		-- Mode A plans carry no arg.strategy — execute unconditionally;
		-- Mode B conf plans filter by the published id.
		if not strat or strat == id then
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

-- Mode A equivalent of orchestrate(): the plan table is already built —
-- execution_plan(ctx) (C-side, config-only) must NOT be consulted.
function orchestrate_apply_dynamic(_ctx, desync)
	desync.plan = desync.plan or {}
end

function bs_timer_poll_strategy(name, data)
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
	-- Mode A: refresh the dynamic plan (file io ONLY here, never per packet).
	bs_poll_strategy_cmd()
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
				id = tonumber(_G.bs_active_id) or 1,
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
				id = tonumber(_G.bs_active_id) or 1,
				gen = tonumber(_G.bs_active_gen) or 0,
				ms = 0,
			})
		end
	end
end
