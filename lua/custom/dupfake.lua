-- dupfake: nfqws2 аналог winws --dpi-desync=fake --dpi-desync-repeats=N
-- отправляет N копий blob с тем же seq (дубликаты), badsum для отбрасывания сервером
--
-- Источник: Keenetic router /opt/etc/nfqws2/lua/dupfake.lua (2026-07-19).
-- Проверено в проде: dupfake:blob=tls_clienthello:repeats=6:tcp_ts=-1000 (YouTube TLS ✅,
-- Discord ❌); dupfake:blob=stun+max_ru:repeats=6:tcp_ts=-1000 — General.
-- Подключение: nfqws2 --lua-init=@.../dupfake.lua или BLOCKCHECKS_LUA_EXTRA.
-- См. lua/custom/README.md.

function dupfake(ctx, desync)
    if not desync.dis.tcp then return end
    direction_cutoff_opposite(ctx, desync)
    if not direction_check(desync) then return end
    if not payload_check(desync) then return end
    if not replay_first(desync) then return end

    local blob_name = desync.arg.blob
    if not blob_name then error("dupfake: 'blob' arg required") end

    local fake_data = blob(desync, blob_name)
    if not fake_data then
        if desync.arg.optional then
            DLOG("dupfake: blob '"..blob_name.."' not found, skip")
            return
        end
        error("dupfake: blob '"..blob_name.."' not found")
    end

    local repeats = tonumber(desync.arg.repeats) or 1
    local orig_seq = desync.dis.tcp and desync.dis.tcp.th_seq or 0

    for i = 1, repeats do
        local copy = deepcopy(desync.dis)
        copy.payload = fake_data
        -- тот же seq, что у оригинала (дубликат, не вставка в поток)
        copy.tcp.th_seq = orig_seq
        -- применение badsum (испорченная checksum — сервер отбросит)
        apply_fooling(desync, copy)
        -- отправка одной копии (повтор через loop = явный repeats)
        local opts = desync_opts(desync)
        opts.rawsend.repeats = 1
        rawsend_dissect_ipfrag(copy, opts)
    end

    -- применение badsum к оригиналу (сервер отбросит если примут фейк)
    apply_fooling(desync, desync.dis)

    DLOG("dupfake: sent "..repeats.."x"..#fake_data.."B seq="..orig_seq)
end
