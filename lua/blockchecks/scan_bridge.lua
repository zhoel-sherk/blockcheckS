-- blockcheckS scan_pick orchestrator + ClientHello strategy poll

_G.bs_active_id = 1
_G.bs_active_gen = 0

function bs_poll_strategy(ctx, desync)
	if desync.l7payload ~= "tls_client_hello" then return end
	if not replay_first(desync) then return end
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
end

function scan_pick(ctx, desync)
	if desync.l7payload ~= "tls_client_hello" then return end
	if not replay_first(desync) then return end
	local id, gen = bs_read_strategy_ipc()
	if id then
		_G.bs_active_id = id
		if gen then _G.bs_active_gen = gen end
	end
	orchestrate(ctx, desync)
	local id = tonumber(_G.bs_active_id) or 1
	local verdict = VERDICT_PASS
	while true do
		local inst = plan_instance_pop(desync)
		if not inst then break end
		local strat = tonumber(inst.arg.strategy)
		if strat and strat == id then
			verdict = plan_instance_execute(desync, verdict, inst)
		end
	end
	bs_write_ipc({
		event = "APPLIED",
		id = id,
		gen = tonumber(_G.bs_active_gen) or 0,
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
