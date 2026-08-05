-- blockcheckS bridge init: timer fallback for strategy.id poll (50ms)

timer_set("bs_poll", "bs_timer_poll_strategy", 50, false, nil)
