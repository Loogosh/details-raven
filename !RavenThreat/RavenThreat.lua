-- !RavenThreat :: анализатор угрозы по логу боя + обмен по GUID/имени.
--
-- Ключ цели не «голый GUID» (он бывает nil), а строка с типом:
--   "G:0xF130..." — есть GUID (точное совпадение между клиентами);
--   "N:Scarlet Defender" — GUID нет, сравниваем по имени.
-- Так пакет не ломается на клиентах/юнитах без GUID, а при наличии GUID
-- остаётся точная идентификация цели.
--
-- Сервер threat на 1.14.2 не отдаёт (замерено), поэтому считаем по логу боя;
-- присланное чужим клиентом число приоритетнее локальной оценки.

local ADDON, ns = ...

local SEP = string.char(1)
local LOG_PATH = 'Logs\\RavenThreat.log'
local HEAL_FACTOR = 0.5
local MAX_TARGETS = 32
local COMM_PREFIX = 'RT2'
local COMM_INTERVAL = 1.0
local TWT_PREFIX = 'TWT'          -- серверный threat Turtle (TWThreat-протокол)
local TWT_REQUEST = 'TWT_UDTSv4'   -- запрос списка угрозы
local TWT_INTERVAL = 2.0

local myGUID, petGUID

-- Плоская угроза способностей (ванильные значения, приблизительно).
local FLAT_THREAT = {
	['Sunder Armor'] = 260,
	['Heroic Strike'] = 145,
	['Revenge'] = 355,
	['Shield Slam'] = 250,
	['Thunder Clap'] = 130,
	['Demoralizing Shout'] = 43,
	['Battle Shout'] = 55,
	['Maul'] = 75,
	['Swipe'] = 100,
	['Growl'] = 0,
}

local unitByGUID = {}
local petOwner = {}

local function rebuildUnits()
	unitByGUID = {}
	petOwner = {}
	local function map(unit, pet)
		local g = UnitGUID(unit)
		if g then unitByGUID[g] = unit end
		if pet and g then
			local p = UnitGUID(pet)
			if p then petOwner[p] = g; unitByGUID[p] = pet end
		end
	end
	map('player', 'pet')
	for i = 1, 4 do map('party' .. i, 'partypet' .. i) end
	for i = 1, 40 do map('raid' .. i, 'raidpet' .. i) end
end

local function unitFor(key)
	if type(key) ~= 'string' then return nil end
	return unitByGUID[key:sub(3)]
end

local function multFor(unit)
	if not unit then return 1 end
	local function has(spellID)
		local name = GetSpellInfo and GetSpellInfo(spellID)
		if not name then return false end
		for i = 1, 32 do
			local buff = UnitBuff(unit, i)
			if not buff then break end
			if buff == name then return true end
		end
		return false
	end
	if has(71) or has(5487) or has(9634) then return 1.3 end  -- Defensive / Bear / Dire Bear
	if has(25780) then return 1.6 end                          -- Righteous Fury
	if has(768) then return 0.71 end                           -- Cat Form
	if has(2457) or has(2458) then return 0.8 end            -- Battle / Berserker
	return 1
end

local threat = {}   -- [targetKey][sourceKey] = value (локальный лог)
local remote = {}   -- [targetKey][sourceKey] = value (прислали другие)
local server = {}   -- [targetKey][sourceKey] = value (ответ сервера TWTv4=)
local order = {}

local function log(fmt, ...)
	local ok, text = pcall(string.format, fmt, ...)
	if not ok then return end
	local gate = _G.RavenEraGate
	if type(gate) ~= 'function' then return end
	pcall(gate, 'AppendFile', LOG_PATH .. SEP .. date('%H:%M:%S') .. ' ' .. text .. '\n')
end

-- Ключ юнита: GUID, иначе имя. nil — юнит без идентичности (пропускаем).
local function keyFor(unit)
	if type(unit) ~= 'string' then return nil end
	local ok, guid = pcall(UnitGUID, unit)
	if ok and type(guid) == 'string' and guid ~= '' then
		return 'G:' .. guid
	end
	local okN, name = pcall(UnitName, unit)
	if okN and type(name) == 'string' and name ~= '' then
		return 'N:' .. name
	end
	return nil
end

local function clearTarget(targetKey)
	if not targetKey then return end
	threat[targetKey] = nil
	remote[targetKey] = nil
	server[targetKey] = nil
	for i = #order, 1, -1 do
		if order[i] == targetKey then
			table.remove(order, i)
		end
	end
end

local function bucket(targetKey)
	local t = threat[targetKey]
	if not t then
		t = {}
		threat[targetKey] = t
		order[#order + 1] = targetKey
		if #order > MAX_TARGETS then
			local old = table.remove(order, 1)
			threat[old] = nil
			remote[old] = nil
			server[old] = nil
		end
	end
	return t
end

local function add(targetKey, sourceKey, amount)
	if not targetKey or not sourceKey or not amount or amount <= 0 then return end
	local t = bucket(targetKey)
	t[sourceKey] = (t[sourceKey] or 0) + amount
end

local function ownerKey(sourceKey)
	if type(sourceKey) == 'string' and sourceKey:sub(1,2) == 'G:' then
		local owner = petOwner[sourceKey:sub(3)]
		if owner then return 'G:' .. owner end
	end
	if petGUID and myGUID and sourceKey == ('G:' .. petGUID) then
		return 'G:' .. myGUID
	end
	return sourceKey
end

--------------------------------------------------------------------------------
-- лог боя
--------------------------------------------------------------------------------

local function onCombatLog()
	local info = { CombatLogGetCurrentEventInfo() }
	local subevent = info[2]
	if type(subevent) ~= 'string' then return end

	-- Death must clear before the sourceGUID gate: UNIT_DIED often has empty source.
	-- Stale buckets after respawn made UnitThreatSituation return status 0 → green plates.
	if subevent == 'UNIT_DIED' or subevent == 'PARTY_KILL' or subevent == 'UNIT_DESTROYED' then
		local deadGUID = info[8]
		if type(deadGUID) == 'string' and deadGUID ~= '' then
			clearTarget('G:' .. deadGUID)
		end
		return
	end

	local sourceGUID, destGUID = info[4], info[8]
	if type(sourceGUID) ~= 'string' or type(destGUID) ~= 'string' then return end

	local targetKey = 'G:' .. destGUID
	local sourceKey = ownerKey('G:' .. sourceGUID)

	if subevent == 'SWING_DAMAGE' then
		local amount = tonumber(info[12])
		if amount and amount > 0 then add(targetKey, sourceKey, amount * multFor(unitFor(sourceKey))) end
		return
	end

	if subevent == 'SPELL_DAMAGE' or subevent == 'SPELL_PERIODIC_DAMAGE'
		or subevent == 'RANGE_DAMAGE' or subevent == 'DAMAGE_SHIELD'
		or subevent == 'DAMAGE_SPLIT' then
		local amount = tonumber(info[15])
		if amount and amount > 0 then add(targetKey, sourceKey, amount * multFor(unitFor(sourceKey))) end
		return
	end

	if subevent == 'SPELL_CAST_SUCCESS' then
		local spellId = tonumber(info[12])
		local name = spellId and GetSpellInfo and GetSpellInfo(spellId)
		local flat = name and FLAT_THREAT[name]
		if flat and flat > 0 then
			local dest = info[8]
			local targetKey
			if dest and dest ~= '0000000000000000' then
				targetKey = 'G:' .. dest
			else
				targetKey = keyFor('target')
			end
			if targetKey then add(targetKey, ownerKey('G:' .. sourceGUID), flat) end
		end
		return
	end

	if subevent == 'SPELL_HEAL' or subevent == 'SPELL_PERIODIC_HEAL' then
		local amount = tonumber(info[15])
		if amount and amount > 0 and destGUID ~= sourceGUID then
			local tKey = keyFor('target')
			if tKey then add(tKey, sourceKey, amount * HEAL_FACTOR) end
		end
	end
end

--------------------------------------------------------------------------------
-- обмен: ключ в пакете — G:guid или N:name
--------------------------------------------------------------------------------

local nameToKey = {}

local function keyForName(name)
	if not name or name == '' then return nil end
	if name == UnitName('player') then return keyFor('player') end
	if nameToKey[name] then return nameToKey[name] end

	local units = { 'player' }
	for i = 1, 4 do units[#units + 1] = 'party' .. i end
	for i = 1, 40 do units[#units + 1] = 'raid' .. i end

	for _, unit in ipairs(units) do
		if UnitName(unit) == name then
			local key = keyFor(unit)
			if key then nameToKey[name] = key end
			return key
		end
	end
	return nil
end

local function broadcast()
	local targetKey = keyFor('target')
	if not targetKey then return end
	local selfKey = keyFor('player')
	if not selfKey then return end

	local value = threat[targetKey] and threat[targetKey][selfKey] or 0
	if value <= 0 then return end

	local channel = IsInRaid() and 'RAID' or (IsInGroup() and 'PARTY' or nil)
	if not channel then return end

	-- В пакете оба ключа: получатель с GUID возьмёт G:, без GUID — N:.
	local payload = targetKey
	local name = UnitName('target')
	if type(name) == 'string' and name ~= '' then
		payload = payload .. '~N:' .. name
	end
	SendAddonMessage(COMM_PREFIX, payload .. '|' .. string.format('%d', math.floor(value)), channel)
end

local function onAddonMessage(prefix, msg, _, sender)
	if type(msg) ~= 'string' then return end

	-- Ответ сервера в формате TWThreat: TWTv4=Name:1:12345:45:1;...
	if prefix == TWT_PREFIX then
		local data = msg:match('TWTv4=(.*)$')
		if not data then return end
		local targetKey = keyFor('target')
		if not targetKey then return end
		local t = server[targetKey]
		if not t then t = {}; server[targetKey] = t end
		for entry in data:gmatch('[^;]+') do
			local name, threatValue = entry:match('^([^:]+):[^:]*:([%-%d]+)')
			local value = tonumber(threatValue)
			if name and value then
				local sKey = keyForName(name)
				if sKey then t[sKey] = value end
			end
		end
		return
	end

	if prefix ~= COMM_PREFIX then return end
	local keys, value = msg:match('^(.-)|(%d+)$')
	value = tonumber(value)
	if not keys or not value then return end

	local sourceKey = keyForName(sender)
	if not sourceKey then return end

	for part in keys:gmatch('[^~]+') do
		local key = part
		-- совместимость: старый формат «голый GUID»
		if key:sub(1, 2) ~= 'G:' and key:sub(1, 2) ~= 'N:' then
			key = 'G:' .. key
		end
		local t = remote[key]
		if not t then t = {}; remote[key] = t end
		t[sourceKey] = value
	end
end

--------------------------------------------------------------------------------
-- наружу
--------------------------------------------------------------------------------

local function valueFor(targetKey, sourceKey)
	local remoteValue = remote[targetKey] and remote[targetKey][sourceKey]
	if remoteValue then return remoteValue end
	return threat[targetKey] and threat[targetKey][sourceKey] or 0
end

local function bestFor(targetKey)
	local best = 0
	-- нельзя ipairs({a,b,c}): при a=nil таблица начинается с индекса 2,
	-- ipairs останавливается сразу и best остаётся 0.
	local function scan(tbl)
		if not tbl then return end
		for _, v in pairs(tbl) do
			if v > best then best = v end
		end
	end
	scan(server[targetKey])
	scan(threat[targetKey])
	scan(remote[targetKey])
	return best
end

local function estimate(sourceUnit, targetUnit)
	local tKey = keyFor(targetUnit)
	local sKey = keyFor(sourceUnit)
	if not tKey or not sKey then return nil end
	if not threat[tKey] and not remote[tKey] then return nil end

	local value = valueFor(tKey, sKey)
	local best = bestFor(tKey)
	if best <= 0 then return nil end

	local pct = (value / best) * 100
	local status
	if value <= 0 then
		status = 0
	elseif pct >= 100 then
		status = 3
	elseif pct >= 90 then
		status = 2
	elseif pct >= 50 then
		status = 1
	else
		status = 0
	end
	return true, (pct >= 100), status, pct, pct, value
end

local function shimDetailed(source, target)
	if type(source) ~= 'string' or type(target) ~= 'string' then return nil end
	if UnitIsDead(target) then return nil end
	local hasData, isTanking, status, pct, raw, value = estimate(source, target)
	if not hasData then return nil end
	return isTanking, status, pct, raw, value
end

local function shimSimple(source, target)
	if type(source) ~= 'string' or type(target) ~= 'string' then return nil end
	local hasData, _, status = estimate(source, target)
	if not hasData then return nil end
	return status
end

-- В этом клиенте окружение аддона может быть песочницей: пишем явно в _G.
_G.__ravenThreatShim = shimDetailed
_G.UnitDetailedThreatSituation = shimDetailed
_G.UnitThreatSituation = shimSimple

--------------------------------------------------------------------------------
-- события
--------------------------------------------------------------------------------

local frame = CreateFrame('Frame')
frame:RegisterEvent('PLAYER_LOGIN')
frame:RegisterEvent('PLAYER_ENTERING_WORLD')
frame:RegisterEvent('PLAYER_TARGET_CHANGED')
frame:RegisterEvent('CHAT_MSG_ADDON')
pcall(frame.RegisterEvent, frame, 'COMBAT_LOG_EVENT_UNFILTERED')

frame:SetScript('OnEvent', function(self, event, ...)
	if event == 'COMBAT_LOG_EVENT_UNFILTERED' then
		onCombatLog()
		return
	end
	if event == 'CHAT_MSG_ADDON' then
		onAddonMessage(...)
		return
	end
	if event == 'PLAYER_LOGIN' or event == 'PLAYER_ENTERING_WORLD' or event == 'GROUP_ROSTER_UPDATE' or event == 'PARTY_MEMBERS_CHANGED' then
		myGUID = UnitGUID('player')
		petGUID = UnitGUID('pet')
		rebuildUnits()
	end
end)

frame:SetScript('OnUpdate', (function()
	local acc, twtAcc = 0, 0
	return function(_, elapsed)
		acc = acc + elapsed
		twtAcc = twtAcc + elapsed
		if acc >= COMM_INTERVAL then
			acc = 0
			broadcast()
		end
		if twtAcc >= TWT_INTERVAL then
			twtAcc = 0
			local channel = IsInRaid() and 'RAID' or (IsInGroup() and 'PARTY' or nil)
			if channel then pcall(SendAddonMessage, TWT_REQUEST, 'limit=20', channel) end
		end
	end
end)())

_G.RavenThreatAPI = {
	threat = threat,
	remote = remote,
	keyFor = keyFor,
	version = 8,
}

log('RavenThreat v8: clear on UNIT_DIED; dead target → nil')









