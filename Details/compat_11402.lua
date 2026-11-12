-- Details :: совместимость с 1.14.2
--
-- Клиент 1.14.2 не имеет пространства C_SpellBook, а Details (собранный под 1.14.4)
-- вызывает его в core/gears.lua без проверки: C_SpellBook.GetOverrideSpell(spellId).
-- На 1.14.2 это ошибка при построении списка заклинаний специализации.
--
-- Заглушка возвращает id без изменений: на Classic замены рангов и так нет, поведение
-- совпадает с ожидаемым. Файл грузится первым, до libs.xml.
if not C_SpellBook then
  C_SpellBook = {
    GetOverrideSpell = function(spellID) return spellID end,
  }
end