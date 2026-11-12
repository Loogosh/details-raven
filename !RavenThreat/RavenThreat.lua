-- !RavenThreat :: оценка угрозы по журналу боя.
--
-- Зачем. Клиент 1.14.2 отдаёт UnitDetailedThreatSituation, но она всегда возвращает nil:
-- сервер угрозу не передаёт (проверено 9 снимками в бою). Из-за этого блок угрозы не
-- работает ни в Details (Details_TinyThreat), ни в CinderMeter — оба читают эту функцию.
--
-- Что делаем. Считаем угрозу сами по журналу боя и ПОДМЕНЯЕМ клиентскую функцию своей.
-- Аддон с "!" в имени грузится первым, поэтому метры захватывают в локальные переменные уже
-- нашу версию и начинают показывать числа.
--
-- Модель (как в HunterAggroMeter): угроза от урона считается 1:1, хил по питомцу даёт
-- 0.5 от объёма. Абсолютные значения — это накопленный урон, а проценты считаются
-- относительно лучшего в списке, чтобы полосы метра имели смысл.
--
-- Ограничение, о котором надо помнить: это ОЦЕНКА, а не серверная угроза. У разных
-- способностей разные коэффициенты угрозы, которых мы не видим.

local ADDON, ns = ...

-- DLL file debug disabled in this release build (threat math still runs).
local SEP = string.char(1)
local LOG_PATH = 'Logs\\RavenDebug.txt'
local DLL_FILE_DEBUG = false

local function Log(tag, fmt, ...)
  if not DLL_FILE_DEBUG then return end
  local text
  if select('#', ...) > 0 then
    local ok, formatted = pcall(string.format, fmt, ...)
    text = ok and formatted or tostring(fmt)
  else
    text = tostring(fmt)
  end
  local line = date('%H:%M:%S') .. ' [' .. tostring(tag) .. '] ' .. text .. '\n'
  local wrapper = _G.RavenEra
  if type(wrapper) == 'function' then
    if pcall(wrapper, 'AppendFile', LOG_PATH, line) then return end
  end
  local lib = _G.RavenEraLib
  if lib and lib.Sept then
    if pcall(lib.Sept, lib, 'AppendFile', LOG_PATH, line) then return end
  end
  local raw = _G.RavenEraGate
  if type(raw) == 'function' then
    pcall(raw, 'AppendFile', LOG_PATH .. SEP .. line)
  end
end
local BOOT_PATH = 'Logs\\RavenThreatBoot.txt'
-- boot / self-check file probes skipped when DLL_FILE_DEBUG is false
local THREAT_MELEE = 1.10     -- 110% ближний бой
local THREAT_RANGED = 1.30    -- 130% дальний бой
local HEAL_FACTOR = 0.5       -- хил создаёт половину угрозы от объёма

local byTarget = {}           -- [guid цели] = { [guid источника] = накопленная угроза }
local targetOrder = {}        -- порядок целей, чтобы чистить старые
local MAX_TARGETS = 8

local myGUID = nil
local petGUID = nil
local playerName = nil
local petName = nil

local function lowGuid(guid)
  return guid and string.match(guid, '(%x+)$') or nil
end

local function forgetOldTargets(keep)
  local count = 0
  for guid in pairs(byTarget) do
    if guid ~= keep then count = count + 1 end
  end
  if count < MAX_TARGETS then return end
  for guid in pairs(byTarget) do
    if guid ~= keep then byTarget[guid] = nil end
  end
end

local function bucket(guid)
  local entry = byTarget[guid]
  if not entry then
    entry = {}
    byTarget[guid] = entry
  end
  return entry
end

-- ---------------------------------------------------------------- разбор журнала
local function onCombatLog()
  local info = { CombatLogGetCurrentEventInfo() }
  local subevent = info[2]
  if type(subevent) ~= 'string' then return end

  local sourceGUID, destGUID = info[4], info[8]

  if subevent:find('_DAMAGE$') or subevent == 'SWING_DAMAGE' then
    -- У заклинаний сначала три параметра заклинания, у удара — сразу сумма
    local amount
    if subevent:find('^SWING_') then
      amount = info[12]
    elseif subevent:find('^SPELL_') or subevent:find('^RANGE_') then
      amount = info[15]
    elseif subevent:find('^DAMAGE_') then
      amount = info[12]
    end
    amount = tonumber(amount)
    if not amount or amount <= 0 then return end
    if not sourceGUID or not destGUID then return end

    local entry = bucket(destGUID)
    entry[sourceGUID] = (entry[sourceGUID] or 0) + amount
    forgetOldTargets(destGUID)
    return
  end

  -- Хил по питомцу добавляем игроку: половина объёма
  if subevent == 'SPELL_HEAL' then
    if petGUID and destGUID == petGUID and myGUID then
      local amount = tonumber(info[15])
      if amount and amount > 0 then
        local target = UnitGUID('target')
        if target then
          local entry = bucket(target)
          entry[myGUID] = (entry[myGUID] or 0) + amount * HEAL_FACTOR
        end
      end
    end
  end
end

-- ---------------------------------------------------------------- оценка
local function estimate(sourceGUID, targetGUID)
  local entry = byTarget[targetGUID]
  if not entry then return nil end

  local value = entry[sourceGUID]
  if not value then
    -- источник ещё ничего не сделал, но данные по цели есть
    value = 0
  end

  local best = 0
  for _, other in pairs(entry) do
    if other > best then best = other end
  end
  if best <= 0 then return nil end

  local scaled = (value / best) * 100
  local status
  if value <= 0 then
    status = 0
  elseif value >= best then
    status = 3
  elseif scaled >= 90 then
    status = 2
  elseif scaled >= 50 then
    status = 1
  else
    status = 0
  end

  -- Первое возвращаемое — "данные есть", а не "танкует". Раньше здесь стояло условие
  -- scaled >= 100, из-за чего шим отдавал nil всем, кроме лидера по угрозе, и метры
  -- показывали только одну строку.
  return true, (scaled >= 100), status, scaled, scaled, value
end

-- ---------------------------------------------------------------- подмена API
local originalDetailed = UnitDetailedThreatSituation
local originalSimple = UnitThreatSituation

local function shimDetailed(source, target)
  -- Оригинал на этом клиенте всегда возвращает nil, а при неверных аргументах ещё и
  -- выдаёт 'Usage: UnitDetailedThreatSituation("unit" [, "mob"])'. Поэтому его не зовём
  -- вовсе: наши данные либо есть, либо функция возвращает nil.
  if type(source) ~= 'string' or type(target) ~= 'string' then return nil end

  local targetGUID = UnitGUID(target)
  local sourceGUID = UnitGUID(source)
  if not targetGUID or not sourceGUID then return nil end

  local hasData, isTanking, status, scaled, raw, value = estimate(sourceGUID, targetGUID)
  if not hasData then return nil end

  return isTanking, status, scaled, raw, value
end

local function shimSimple(source, target)
  local ok, status = shimDetailed(source, target)
  if not ok then return nil end
  return status
end

UnitDetailedThreatSituation = shimDetailed
UnitThreatSituation = shimSimple

-- ---------------------------------------------------------------- события
local frame = CreateFrame('Frame')
frame:RegisterEvent('PLAYER_LOGIN')
frame:RegisterEvent('PLAYER_ENTERING_WORLD')
frame:RegisterEvent('PLAYER_TARGET_CHANGED')
frame:RegisterEvent('PLAYER_REGEN_ENABLED')
pcall(frame.RegisterEvent, frame, 'COMBAT_LOG_EVENT_UNFILTERED')

frame:SetScript('OnEvent', function(self, event)
  if event == 'COMBAT_LOG_EVENT_UNFILTERED' then
    onCombatLog()
    return
  end

  if event == 'PLAYER_LOGIN' or event == 'PLAYER_ENTERING_WORLD' then
    myGUID = UnitGUID('player')
    petGUID = UnitGUID('pet')
    playerName = UnitName('player')
    petName = UnitName('pet')
    Log('threat', 'оценка угрозы активна: игрок %s, пет %s', tostring(playerName), tostring(petName))
    return
  end

  if event == 'PLAYER_TARGET_CHANGED' then
    petGUID = UnitGUID('pet')
    petName = UnitName('pet')
    return
  end

  if event == 'PLAYER_REGEN_ENABLED' then
    -- бой кончился: оставляем данные, они нужны метрам для итоговой строки,
    -- но чистим по смене цели, чтобы не копилось
    return
  end
end)

-- Наружу — для собственных модулей и диагностики
_G.RavenThreatAPI = {
  version = 1,
  Get = function(source, target)
    return shimDetailed(source, target)
  end,
  Thresholds = { melee = THREAT_MELEE, ranged = THREAT_RANGED, heal = HEAL_FACTOR },
}

-- ---------------------------------------------------------------- порт TWThreat 1.3.0
-- Один в один как в оригинале, только без окна: всё уходит в лог.
--
-- Исходящие (номера строк TWThreat.lua):
--   :2521-2524  TWTVersion:<версия>  -> PARTY, GUILD, RAID, BATTLEGROUND при входе в мир
--   :334        TWT_ME:<версия>      -> ответ на TWT_WHO
--   :1207-1208  TWT_UDTSv4 'limit=4' -> запрос угрозы, канал RAID или PARTY
--   :1203-1204  TWT.send(msg)        -> SendAddonMessage('TWT', msg, канал)
--
-- Входящие на префиксе TWT:
--   :319  TWTVersion:<в>  — версия у другого игрока
--   :333  TWT_WHO         — отвечаем TWT_ME
--   :338  TWTRoleTexture: — иконка роли игрока
--   :344  TWT_ME:<в>      — у игрока есть аддон
--
-- Угроза приходит телом с 'TWTv4=', записи через ';', поля через ':'
-- (имя:танк:угроза:процент:ближний). Танк-режим — блок после '#' с меткой 'TMTv1='.
local ADDON_VERSION = '1.3.0'
local BARS = 5                        -- TWT.minBars по умолчанию
local LIMIT = BARS - 1                -- в запрос уходит limit=4
local PREFIX = 'TWT'                  -- TWT.prefix
local UDTS = 'TWT_UDTSv4'             -- TWT.UDTS
local UDTS_TM = 'TWT_UDTSv4_TM'       -- TWT.UDTS .. '_TM'
local THREAT_API = 'TWTv4='           -- TWT.threatApi
local TANK_API = 'TMTv1='             -- TWT.tankModeApi

local PREFIXES = { PREFIX, UDTS, UDTS_TM, 'TWTv4', 'TMTv1' }
if C_ChatInfo and C_ChatInfo.RegisterAddonMessagePrefix then
  for i = 1, #PREFIXES do
    pcall(C_ChatInfo.RegisterAddonMessagePrefix, PREFIXES[i])
  end
end

-- TWT.channel: RAID если в рейде, иначе PARTY (:1132)
local function channel()
  if IsInRaid and IsInRaid() then return 'RAID' end
  return 'PARTY'
end

-- TWT.send (:1203)
local function send(message)
  if not (C_ChatInfo and C_ChatInfo.SendAddonMessage) then return false end
  local ok, sent = pcall(C_ChatInfo.SendAddonMessage, PREFIX, message, channel())
  return ok and sent
end

-- TWT.sendMyVersion (:2520)
local function sendMyVersion()
  if not (C_ChatInfo and C_ChatInfo.SendAddonMessage) then return end
  local channels = { 'PARTY', 'GUILD', 'RAID', 'BATTLEGROUND' }
  for i = 1, #channels do
    pcall(C_ChatInfo.SendAddonMessage, PREFIX, 'TWTVersion:' .. ADDON_VERSION, channels[i])
  end
end

local lastRequestSignature
-- TWT.UnitDetailedThreatSituation (:1207)
local function requestThreat()
  if not (C_ChatInfo and C_ChatInfo.SendAddonMessage) then return end
  local ch = channel()
  local ok, sent = pcall(C_ChatInfo.SendAddonMessage, UDTS, 'limit=' .. LIMIT, ch)
  local signature = ch .. tostring(sent)
  if signature ~= lastRequestSignature then
    lastRequestSignature = signature
    Log('threat', 'запрос угрозы: limit=%d канал=%s ok=%s отправлено=%s',
      LIMIT, ch, tostring(ok), tostring(sent))
  end
end

-- TWT.handleTankModePacket: блок после '#'
local function handleTankMode(packet)
  Log('threat', 'танк-режим: %s', tostring(packet))
end

-- TWT.handleThreatPacket (:790)
local function handleThreatPacket(text)
  local data, tankPart = text, nil
  if string.find(data, '#', 1, true) and string.find(data, TANK_API, 1, true) then
    local first, second = string.match(data, '^(.-)#(.*)$')
    if first then data, tankPart = first, second end
  end

  local body = string.match(data, 'TWTv4=(.*)')
  if not body then return end
  if tankPart then handleTankMode(tankPart) end

  local rows, count = {}, 0
  for entry in string.gmatch(body, '[^;]+') do
    local name, tank, threat, pct, melee = string.match(entry, '^([^:]+):(%d+):(%-?%d+):(%-?%d+):(%d+)')
    if name then
      count = count + 1
      if count <= BARS then
        rows[#rows + 1] = string.format('%s: угроза=%s %s%% танк=%s ближний=%s',
          name, threat, pct, tank, melee)
      end
    end
  end

  Log('threat', 'пакет угрозы: записей %d', count)
  for i = 1, #rows do Log('threat', '  %s', rows[i]) end

  ns.lastThreat = { at = GetTime(), count = count, rows = rows }
end

-- Общий приём аддон-сообщений (:298 и :318)
local watch = CreateFrame('Frame')
pcall(watch.RegisterEvent, watch, 'CHAT_MSG_ADDON')
watch:SetScript('OnEvent', function(_, event, prefix, text, channelType, sender)
  if type(text) ~= 'string' then return end

  -- пакеты угрозы проверяем по телу, как оригинал (:298)
  if string.find(text, THREAT_API, 1, true) then
    handleThreatPacket(text)
    return
  end

  -- служебные сообщения на нашем префиксе (:318)
  if prefix ~= PREFIX then return end

  if string.sub(text, 1, 11) == 'TWTVersion:' then
    Log('threat', 'версия у %s: %s', tostring(sender), tostring(string.sub(text, 12)))
    return
  end

  if string.sub(text, 1, 7) == 'TWT_WHO' then
    send('TWT_ME:' .. ADDON_VERSION)
    Log('threat', 'ответил на TWT_WHO от %s', tostring(sender))
    return
  end

  if string.sub(text, 1, 15) == 'TWTRoleTexture:' then
    ns.roles = ns.roles or {}
    ns.roles[sender] = string.sub(text, 16)
    Log('threat', 'роль %s: %s', tostring(sender), tostring(ns.roles[sender]))
    return
  end

  if string.sub(text, 1, 7) == 'TWT_ME:' then
    ns.hasAddon = ns.hasAddon or {}
    ns.hasAddon[sender] = string.sub(text, 8)
    Log('threat', 'аддон есть у %s: %s', tostring(sender), tostring(ns.hasAddon[sender]))
    return
  end
end)

-- Тик запросов. В оригинале updateUI зовётся по событиям UNIT_THREAT_*, которых на 1.14
-- нет, поэтому тик на OnUpdate: в бою раз в секунду, вне боя раз в пять.
local tick = CreateFrame('Frame')
local elapsed = 0
tick:SetScript('OnUpdate', function(_, delta)
  elapsed = elapsed + delta
  local interval = UnitAffectingCombat('player') and 1 or 5
  if elapsed < interval then return end
  elapsed = 0
  requestThreat()
end)

local login = CreateFrame('Frame')
pcall(login.RegisterEvent, login, 'PLAYER_ENTERING_WORLD')
pcall(login.RegisterEvent, login, 'GROUP_ROSTER_UPDATE')
login:SetScript('OnEvent', function(_, event)
  lastRequestSignature = nil
  if event == 'PLAYER_ENTERING_WORLD' then
    sendMyVersion()
    Log('threat', 'объявил версию %s (PARTY/GUILD/RAID/BATTLEGROUND)', ADDON_VERSION)
  end
  requestThreat()
end)