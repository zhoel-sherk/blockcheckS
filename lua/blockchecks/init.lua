-- blockcheckS bridge init: strategy.id poll (50ms) + daemon heartbeat (200ms)

timer_set("bs_poll", "bs_timer_poll_strategy", 50, false, nil)
timer_set("bs_heartbeat", "bs_write_heartbeat", 200, false, nil)
