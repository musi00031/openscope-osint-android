package com.openscope.osint

import android.content.Context
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Locale

data class Finding(
    val title: String,
    val value: String,
    val detail: String,
    val level: String = "info",
    val section: String = "general"
)

data class AnalysisResult(
    val subject: String,
    val module: String,
    val summary: String,
    val findings: List<Finding>,
    val explanation: String
)

object AnalysisEngine {
    private val publicSearchGate = Semaphore(6)
    suspend fun run(type: String, raw: String, context: Context): AnalysisResult = withContext(Dispatchers.IO) {
        val value = raw.trim()
        when (type) {
            "username" -> username(value, context)
            "social" -> social(value)
            "ukraine" -> ukraineRegistry(value)
            "person" -> person(value)
            "email" -> email(value)
            "ip" -> AdvancedAnalyzers.ip(value)
            "url" -> AdvancedAnalyzers.url(value)
            else -> domain(value)
        }
    }

    private suspend fun username(name: String, context: Context): AnalysisResult = coroutineScope {
        require(name.matches(Regex("[A-Za-z0-9._-]{2,30}"))) { "Никнейм: используйте 2–30 символов: латиница, цифры, точка, дефис или _." }
        val root = JSONObject(context.assets.open("wmn-data.json").bufferedReader().use { it.readText() })
        val allSites = root.getJSONArray("sites")
        val eligible = (0 until allSites.length()).mapNotNull { allSites.optJSONObject(it) }
            .filter { site ->
                site.optBoolean("valid", true) &&
                !site.has("post_body") &&
                site.optString("cat") != "xx NSFW xx" &&
                site.optString("uri_check").startsWith("https://") &&
                !site.optJSONArray("protection").let { protection ->
                    protection != null && (0 until protection.length()).any { i ->
                        protection.optString(i) in listOf("captcha", "cloudflare", "cloudfront", "akamai", "ddos-guard", "user-auth", "multiple")
                    }
                }
            }.take(400)
        val gate = Semaphore(6)
        val checks = eligible.map { site ->
            async(Dispatchers.IO) {
                gate.withPermit {
                    val label = site.optString("name", "Площадка")
                    val template = site.optString("uri_check")
                    val profile = site.optString("uri_pretty", template).replace("{account}", name)
                    val target = template.replace("{account}", URLEncoder.encode(name, "UTF-8"))
                    val url = runCatching { URL(target) }.getOrNull()
                    if (url == null || url.protocol != "https") return@withPermit Finding(label, "Пропущено", "Некорректный или небезопасный URL.", "warn")
                    val response = requestBody(target)
                    val expectedCode = site.optInt("e_code", -2)
                    val missingCode = site.optInt("m_code", -3)
                    val expectedText = site.optString("e_string")
                    val missingText = site.optString("m_string")
                    when {
                        response.first == expectedCode && expectedText.isNotBlank() && response.second.contains(expectedText, true) ->
                            Finding(label, "Возможный профиль найден", profile, "good")
                        response.first == missingCode && (missingText.isBlank() || response.second.contains(missingText, true)) ->
                            Finding(label, "Профиль не обнаружен", profile, "info")
                        response.first < 0 -> Finding(label, "Нет ответа", "Тайм-аут или сетевая ошибка.", "warn")
                        response.first == 403 || response.first == 429 -> Finding(label, "Ограничение источника", "HTTP " + response.first, "warn")
                        else -> Finding(label, "Неоднозначно", "HTTP " + response.first + "; сигнатура не совпала.", "warn")
                    }
                }
            }
        }.awaitAll()
        val found = checks.filter { it.level == "good" }
        val uncertain = checks.count { it.level == "warn" }
        val findings = mutableListOf<Finding>()
        findings += found.take(80)
        findings += Finding("Покрытие", eligible.size.toString() + " публичных GET-площадок", "Использован локально упакованный набор WhatsMyName. Из полного набора исключены NSFW, POST-проверки, CAPTCHA/Cloudflare и другие защищённые сайты.", "good")
        findings += Finding("Неоднозначные ответы", uncertain.toString(), "Сайты с антибот-защитой, тайм-аутами или изменившейся разметкой не засчитываются как найденные.", if (uncertain > 0) "warn" else "info")
        // A normal username investigation must include social networks too.
        // Previously users had to discover and select a separate Social chip.
        val socialResult = runCatching { social(name) }.getOrNull()
        if (socialResult != null) {
            findings += Finding("Проверка социальных сетей", socialResult.summary,
                "Дополнительно выполнен поиск по Telegram, Instagram, TikTok, Facebook, YouTube, VK, X, Threads, LinkedIn, Pinterest, Twitch, Reddit, GitHub и Medium через два независимых публичных поисковых индекса.", "info")
            findings += socialResult.findings
        } else {
            findings += Finding("Проверка социальных сетей", "Не удалось завершить",
                "Поисковые источники временно недоступны или вернули ошибку. Это не означает, что аккаунтов нет.", "warn")
        }
        AnalysisResult(name, "Username OSINT · WhatsMyName + Social OSINT",
            "Проверено площадок WhatsMyName: " + eligible.size + "; возможных совпадений: " + found.size + "; неоднозначных ответов: " + uncertain +
                "; соцсети: " + (socialResult?.summary ?: "нет ответа"), findings,
            "Выполнены проверки WhatsMyName и отдельный поиск публичных профилей и упоминаний в социальных сетях. Совпадение — кандидат для ручной проверки, а не доказательство владения аккаунтом или того, что разные профили принадлежат одному человеку. Сайты и поисковые индексы могут ограничивать доступ или обновлять разметку; отсутствие результата ничего не доказывает. Используются только публичные HTTPS GET-запросы; закрытые аккаунты, приватные чаты, авторизация и обход ограничений не выполняются.")
    }

    private fun requestBody(address: String): Pair<Int, String> {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return -1 to ""
        return try {
            connection.connectTimeout = 6500
            connection.readTimeout = 6500
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            val code = connection.responseCode
            val stream = if (code in 200..399) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText().take(300_000) }.orEmpty()
            code to body
        } catch (_: Exception) { -1 to "" } finally { connection.disconnect() }
    }

    private data class SearchHit(val title: String, val url: String, val snippet: String, val category: String)

    private suspend fun social(raw: String): AnalysisResult = coroutineScope {
        val handle = raw.trim().removePrefix("@")
        require(handle.matches(Regex("[A-Za-z0-9._-]{2,40}"))) {
            "Введите публичный никнейм: 2–40 символов, латиница, цифры, точка, дефис или подчёркивание."
        }
        data class SocialTarget(val name: String, val domains: Set<String>, val queries: List<String>, val directUrl: String)
        val h = handle.lowercase(Locale.ROOT)
        val targets = listOf(
            SocialTarget("Telegram", setOf("t.me", "telegram.me"), listOf("site:t.me \"$handle\"", "site:telegram.me \"$handle\"", "site:t.me $handle"), "https://t.me/$handle"),
            SocialTarget("Instagram", setOf("instagram.com"), listOf("site:instagram.com/$handle", "site:instagram.com \"$handle\"", "site:instagram.com $handle"), "https://www.instagram.com/$handle/"),
            SocialTarget("TikTok", setOf("tiktok.com"), listOf("site:tiktok.com/@$handle", "site:tiktok.com \"$handle\""), "https://www.tiktok.com/@$handle"),
            SocialTarget("Facebook", setOf("facebook.com"), listOf("site:facebook.com \"$handle\"", "site:facebook.com $handle"), "https://www.facebook.com/$handle"),
            SocialTarget("YouTube", setOf("youtube.com"), listOf("site:youtube.com/@$handle", "site:youtube.com \"$handle\""), "https://www.youtube.com/@$handle"),
            SocialTarget("VK", setOf("vk.com"), listOf("site:vk.com \"$handle\"", "site:vk.com $handle"), "https://vk.com/$handle"),
            SocialTarget("X / Twitter", setOf("x.com", "twitter.com"), listOf("site:x.com \"$handle\"", "site:twitter.com \"$handle\""), "https://x.com/$handle"),
            SocialTarget("Threads", setOf("threads.net"), listOf("site:threads.net/@$handle", "site:threads.net \"$handle\""), "https://www.threads.net/@$handle"),
            SocialTarget("LinkedIn", setOf("linkedin.com"), listOf("site:linkedin.com/in/$handle", "site:linkedin.com \"$handle\""), "https://www.linkedin.com/in/$handle/"),
            SocialTarget("Pinterest", setOf("pinterest.com"), listOf("site:pinterest.com/$handle", "site:pinterest.com \"$handle\""), "https://www.pinterest.com/$handle/"),
            SocialTarget("Twitch", setOf("twitch.tv"), listOf("site:twitch.tv/$handle", "site:twitch.tv \"$handle\""), "https://www.twitch.tv/$handle"),
            SocialTarget("Reddit", setOf("reddit.com"), listOf("site:reddit.com/user/$handle", "site:reddit.com/u/$handle", "site:reddit.com \"$handle\""), "https://www.reddit.com/user/$handle/"),
            SocialTarget("GitHub", setOf("github.com"), listOf("site:github.com/$handle", "site:github.com \"$handle\""), "https://github.com/$handle"),
            SocialTarget("Medium", setOf("medium.com"), listOf("site:medium.com/@$handle", "site:medium.com \"$handle\""), "https://medium.com/@$handle")
        )
        val gate = Semaphore(5)
        val results = targets.map { target ->
            async(Dispatchers.IO) {
                gate.withPermit {
                    target to searchPublicPages("Публичный поиск · " + target.name, target.queries)
                }
            }
        }.awaitAll()
        val directGate = Semaphore(4)
        val directChecks = targets.map { target ->
            async(Dispatchers.IO) {
                directGate.withPermit { target.name to probePublicProfile(target.directUrl, target.name, handle) }
            }
        }.awaitAll().toMap()
        val findings = mutableListOf<Finding>()
        var profileCandidates = 0
        var directResponded = 0
        results.forEach { (target, hits) ->
            val direct = directChecks[target.name] ?: ("Не удалось проверить" to "Сетевая ошибка или тайм-аут.")
            if (direct.first.startsWith("HTTP 2")) directResponded++
            val unique = hits.distinctBy { it.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT) }
            val profileHits = mutableListOf<SearchHit>()
            val mentionHits = mutableListOf<SearchHit>()
            unique.forEach { hit ->
                val parsed = runCatching { URL(hit.url) }.getOrNull()
                val host = parsed?.host?.lowercase(Locale.ROOT)?.removePrefix("www.").orEmpty()
                val pathParts = parsed?.path.orEmpty().split("/").filter { it.isNotBlank() }.map { it.removePrefix("@").lowercase(Locale.ROOT) }
                val hostMatches = target.domains.any { host == it || host.endsWith(".$it") }
                val pathMatch = when (target.name) {
                    "Telegram" -> pathParts.firstOrNull() == h || (pathParts.firstOrNull() == "s" && pathParts.getOrNull(1) == h)
                    "Instagram", "Threads", "Twitch", "Pinterest", "Medium", "VK", "Facebook" -> pathParts.firstOrNull() == h
                    "TikTok", "YouTube" -> pathParts.any { it == h }
                    "X / Twitter" -> pathParts.firstOrNull() == h
                    "LinkedIn" -> pathParts.firstOrNull() == "in" && pathParts.getOrNull(1) == h
                    "Reddit" -> pathParts.size >= 2 && pathParts[0] in setOf("user", "u") && pathParts[1] == h
                    "GitHub" -> pathParts.firstOrNull() == h
                    else -> false
                }
                if (hostMatches && pathMatch) profileHits += hit
                else if ((hit.title + " " + hit.snippet + " " + hit.url).contains(handle, true)) mentionHits += hit
            }
            profileHits.take(5).forEach { hit ->
                profileCandidates++
                findings += Finding(target.name, hit.title,
                    listOf(hit.url, hit.snippet, "URL совпадает с шаблоном профиля и никнеймом. Это кандидат, а не подтверждение личности или доступности аккаунта.")
                        .filter { it.isNotBlank() }.joinToString("\n"), "good", "social")
            }
            mentionHits.filterNot { candidate -> profileHits.any { it.url == candidate.url } }.take(2).forEach { hit ->
                findings += Finding(target.name + " · упоминание", hit.title,
                    listOf(hit.url, hit.snippet, "Никнейм найден в индексируемом результате; ссылка не подтверждает профиль с таким именем.")
                        .filter { it.isNotBlank() }.joinToString("\n"), "info", "mentions")
            }
            if (profileHits.isEmpty() && mentionHits.isEmpty()) {
                findings += Finding(target.name, "В поисковых индексах не найдено",
                    "DuckDuckGo и Bing не вернули совпадающую страницу. Прямая проверка: " + direct.first + ". " + direct.second +
                        " Поисковая выдача и ответ сайта — разные проверки; отсутствие результата в поиске не означает отсутствие аккаунта.", "info", "social")
            } else {
                findings += Finding(target.name + " · прямая проверка", direct.first, direct.second, "info", "social")
            }
        }

        val globalQueries = listOf(
            "\"$handle\"",
            "$handle Украина OR Україна OR Днепр OR Одесса",
            "\"$handle\" новости OR новини OR форум OR публикация",
            "\"$handle\" site:zmina.info OR site:pravda.com.ua OR site:suspilne.media OR site:hromadske.ua OR site:unian.ua OR site:ukrinform.ua OR site:nv.ua OR site:liga.net OR site:24tv.ua OR site:tsn.ua OR site:focus.ua OR site:censor.net OR site:obozrevatel.com OR site:korrespondent.net"
        )
        val globalHits = searchPublicPages("Упоминания в открытом интернете", globalQueries)
            .distinctBy { it.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT) }
        val newsDomains = setOf(
            "zmina.info", "pravda.com.ua", "suspilne.media", "hromadske.ua", "unian.ua",
            "ukrinform.ua", "nv.ua", "liga.net", "24tv.ua", "tsn.ua", "focus.ua",
            "censor.net", "obozrevatel.com", "korrespondent.net", "babel.ua",
            "radiosvoboda.org", "zn.ua", "detector.media", "apostrophe.ua"
        )
        var newsCount = 0
        var webMentionCount = 0
        globalHits.filter { (it.title + " " + it.snippet + " " + it.url).contains(handle, true) || it.url.contains(h, true) }
            .take(30).forEach { hit ->
                val host = runCatching { URL(hit.url).host.lowercase(Locale.ROOT).removePrefix("www.") }.getOrDefault("")
                val isNews = newsDomains.any { host == it || host.endsWith(".$it") }
                if (isNews) newsCount++ else webMentionCount++
                findings += Finding(
                    if (isNews) "Новостное издание" else "Открытый интернет",
                    hit.title,
                    listOf(hit.url, hit.snippet, "Совпадение найдено поисковым индексом по никнейму; контекст и принадлежность упоминания нужно проверить вручную.")
                        .filter { it.isNotBlank() }.joinToString("\n"),
                    if (isNews) "good" else "info",
                    "mentions"
                )
            }
        findings += Finding("Сводка социальных сетей", "$profileCandidates кандидатов профиля · $directResponded сайтов ответили HTTP 2xx",
            "Проверены 14 платформ через поисковые индексы и отдельные прямые GET-запросы к сформированным адресам. HTTP 2xx означает, что сайт отдал страницу, но не всегда подтверждает существование профиля: некоторые платформы возвращают общую страницу входа или заглушку.", "info", "social")
        findings += Finding("Сводка упоминаний", "Новости: $newsCount · прочий интернет: $webMentionCount",
            "Отдельно выполнен общий поиск по точному нику, украинским вариантам запроса и ряду украинских СМИ. Отсутствие совпадений не доказывает отсутствие публикаций.", "info", "mentions")
        findings += Finding("Прямые адреса и ответы сайтов", "Проверены HTTP-запросами",
            targets.joinToString("\n") { it.name + ": " + it.directUrl + "\n  " + (directChecks[it.name]?.first ?: "Нет ответа") + " — " + (directChecks[it.name]?.second ?: "Проверка не завершена") } +
                "\nHTTP-ответ не равен подтверждению личности. Если платформа блокирует автоматический запрос, откройте ссылку вручную.", "info", "social")
        AnalysisResult(handle, "Social + Web Mentions OSINT",
            "Платформ: " + targets.size + "; кандидатов профиля: " + profileCandidates + "; новостных упоминаний: " + newsCount + "; прочих веб-упоминаний: " + webMentionCount,
            findings,
            "Отчёт разделяет кандидатов публичных профилей в социальных сетях и текстовые упоминания никнейма в СМИ/открытом интернете. Поиск выполняется по публичным индексам DuckDuckGo и Bing несколькими вариантами запросов. Закрытый Instagram-профиль может быть найден только если поисковик ранее проиндексировал его публичную страницу; приватное содержимое, подписчики и публикации за авторизацией не извлекаются. Если результат не найден, это означает только отсутствие результата в проверенных индексах, а не отсутствие аккаунта или публикаций. Совпадения не устанавливают личность владельца.")
    }
    private suspend fun ukraineRegistry(raw: String): AnalysisResult = coroutineScope {
        val subject = raw.trim().replace(Regex("""\s+"""), " ")
        require(subject.length in 3..120 && subject.matches(Regex("""[\p{L}\p{N} .’'&()_-]+"""))) {
            "Введите название украинской компании, организации или код ЕГРПОУ (8 цифр). Не вводите персональные данные частного лица."
        }
        val code = subject.matches(Regex("""\d{8}"""))
        val quoted = if (code) subject else "\"$subject\""
        data class RegistryTarget(val name: String, val domain: String, val query: String, val purpose: String)
        val targets = listOf(
            RegistryTarget("Opendatabot", "opendatabot.ua", "site:opendatabot.ua $quoted", "Карточки компаний и открытые регистрационные сведения"),
            RegistryTarget("YouControl", "youcontrol.com.ua", "site:youcontrol.com.ua $quoted", "Публичные страницы компаний и деловые связи"),
            RegistryTarget("Clarity Project", "clarity-project.info", "site:clarity-project.info $quoted", "Аналитика закупок и участников"),
            RegistryTarget("Prozorro", "prozorro.gov.ua", "site:prozorro.gov.ua $quoted", "Публичные закупки и тендерные объявления"),
            RegistryTarget("Spending.gov.ua", "spending.gov.ua", "site:spending.gov.ua $quoted", "Публичные транзакции и расходы"),
            RegistryTarget("data.gov.ua", "data.gov.ua", "site:data.gov.ua $quoted", "Открытые наборы государственных данных"),
            RegistryTarget("SMIDA", "smida.gov.ua", "site:smida.gov.ua $quoted", "Раскрытие информации эмитентами"),
            RegistryTarget("Минюст Украины", "minjust.gov.ua", "site:minjust.gov.ua $quoted", "Официальные публикации и сервисы Минюста"),
            RegistryTarget("ЕГР Минюста", "usr.minjust.gov.ua", "site:usr.minjust.gov.ua $quoted", "Официальный Единый государственный реестр"),
            RegistryTarget("Судебный реестр", "reyestr.court.gov.ua", "site:reyestr.court.gov.ua $quoted", "Публичные судебные решения; совпадение названия требует ручной проверки"),
            RegistryTarget("Dozorro", "dozorro.org", "site:dozorro.org $quoted", "Публичный мониторинг закупок и отзывы участников"),
            RegistryTarget("АМКУ", "amcu.gov.ua", "site:amcu.gov.ua $quoted", "Публичные решения и сообщения Антимонопольного комитета"),
            RegistryTarget("НБУ", "bank.gov.ua", "site:bank.gov.ua $quoted", "Публичные сведения о финансовом рынке и учреждениях"),
            RegistryTarget("DREAM", "dream.gov.ua", "site:dream.gov.ua $quoted", "Публичные проекты восстановления и инвестиций")
        )
        val gate = Semaphore(4)
        val results = targets.map { target ->
            async(Dispatchers.IO) {
                gate.withPermit {
                    target to searchPublicPages("Украина · ${target.name}", target.query)
                }
            }
        }.awaitAll()
        val findings = mutableListOf<Finding>()
        var indexedPages = 0
        results.forEach { (target, hits) ->
            val valid = hits.filter { hit ->
                val host = runCatching { URL(hit.url).host.lowercase(Locale.ROOT).removePrefix("www.") }.getOrDefault("")
                host == target.domain || host.endsWith("." + target.domain)
            }.distinctBy { it.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT) }.take(5)
            if (valid.isEmpty()) {
                findings += Finding(target.name, "В поисковой выдаче нет проверяемой страницы",
                    target.purpose + ". Поисковая система не вернула индексируемый результат; это не означает отсутствие записи в самом источнике.", "info")
            } else {
                valid.forEach { hit ->
                    indexedPages++
                    findings += Finding(target.name + " · публичная страница", hit.title,
                        listOf(hit.url, hit.snippet, target.purpose, "Проверьте первичную запись и актуальность непосредственно на сайте источника.")
                            .filter { it.isNotBlank() }.joinToString("\n"), "good")
                }
            }
        }
        val openDataHits = async(Dispatchers.IO) { dataGovDatasetSearch(subject) }.await()
        openDataHits.forEach { hit ->
            indexedPages++
            findings += Finding("data.gov.ua · API набора данных", hit.title,
                listOf(hit.url, hit.snippet, "Результат получен напрямую из официального CKAN Action API портала открытых данных. Набор данных может содержать только косвенное упоминание организации.")
                    .filter { it.isNotBlank() }.joinToString("\n"), "good")
        }
        findings += Finding("Прямой API data.gov.ua", if (openDataHits.isEmpty()) "Совпадений в каталоге не найдено" else "${openDataHits.size} наборов данных",
            "Выполнен прямой запрос CKAN package_search к data.gov.ua; это поиск по каталогу наборов данных, а не по всем записям государственных реестров.", if (openDataHits.isEmpty()) "info" else "good")
        findings += Finding("Идентификатор", if (code) "Формат ЕГРПОУ: 8 цифр" else "Поиск по названию",
            if (code) "Поиск выполнялся по указанному коду. Сверьте его с официальной карточкой организации."
            else "Названия могут совпадать у разных юридических лиц. Для точной идентификации используйте код ЕГРПОУ.", if (code) "good" else "warn")
        findings += Finding("Проверка достоверности", "Поисковая выдача не является официальной выпиской",
            "OpenScope показывает ссылки и фрагменты поисковой выдачи. Статус компании, судебное решение, закупку или транзакцию нужно подтверждать первичным документом; учитывайте дату и контекст публикации.", "warn")
        AnalysisResult(subject, "Ukraine Public Records OSINT",
            "Проверено ${targets.size} источников; получено индексируемых публичных страниц: $indexedPages",
            findings,
            "Модуль ориентирован на юридические лица и организации Украины. Источники: Opendatabot, YouControl, Clarity Project, Prozorro, Spending.gov.ua, data.gov.ua, SMIDA, Минюст/ЕГР, публичный судебный реестр, Dozorro, АМКУ, НБУ и DREAM. Используется поиск публичных страниц, а не закрытые базы и не авторизованные кабинеты. Поисковый запрос передаётся DuckDuckGo. Совпадение названия не доказывает связь с конкретным лицом.")
    }

    private suspend fun person(name: String): AnalysisResult = coroutineScope {
        val cleanName = name.trim().replace(Regex("""\s+"""), " ")
        require(cleanName.length in 3..80 && cleanName.matches(Regex("""[\p{L}][\p{L} .’'-]{1,78}[\p{L}]"""))) {
            "Введите имя и фамилию (3–80 символов)."
        }
        // Public-interest search only: no private contact details, home addresses,
        // family mapping, account access, or real-time location searches.
        val queries = listOf(
            "Точное совпадение" to "\"$cleanName\"",
            "Профессиональные публикации" to "\"$cleanName\" (публикация OR конференция OR специалист OR автор)",
            "Научные материалы" to "\"$cleanName\" (ORCID OR исследование OR университет OR журнал)",
            "Новости и интервью" to "\"$cleanName\" (новости OR интервью OR пресс-релиз)"
        )
        val webPages = queries.map { pair ->
            async(Dispatchers.IO) { searchPublicPages(pair.first, pair.second) }
        }.awaitAll().flatten()
        val encyclopediaPages = listOf("ru", "en").map { language ->
            async(Dispatchers.IO) { wikipediaPages(cleanName, language) }
        }.awaitAll().flatten()
        val knowledgePages = listOf("ru", "en").map { language ->
            async(Dispatchers.IO) { wikidataPages(cleanName, language) }
        }.awaitAll().flatten()
        val newsPages = async(Dispatchers.IO) { gdeltNews(cleanName) }.await()
        val scholarlyPages = listOf(
            async(Dispatchers.IO) { openAlexAuthors(cleanName) },
            async(Dispatchers.IO) { crossrefWorks(cleanName) }
        ).awaitAll().flatten()
        val pages = webPages + encyclopediaPages + knowledgePages + newsPages + scholarlyPages
        val unique = linkedMapOf<String, SearchHit>()
        pages.forEach { hit ->
            val key = hit.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT)
            if (key.startsWith("https://") && !unique.containsKey(key)) unique[key] = hit
        }
        val nameTokens = cleanName.lowercase(Locale.ROOT).split(Regex("""\s+""")).filter { it.length > 1 }.toSet()
        fun relevance(hit: SearchHit): Int {
            val text = (hit.title + " " + hit.snippet).lowercase(Locale.ROOT)
            val matched = nameTokens.count { text.contains(it) }
            val exact = if (text.contains(cleanName.lowercase(Locale.ROOT))) 5 else 0
            val source = when {
                hit.category.startsWith("Crossref") -> 4
                hit.category.startsWith("OpenAlex") -> 4
                hit.category.startsWith("Wikidata") -> 3
                hit.category.startsWith("Википедия") -> 2
                hit.category.startsWith("GDELT") -> 2
                else -> 1
            }
            return matched * 3 + exact + source
        }
        val hits = unique.values.sortedWith(
            compareByDescending<SearchHit> { relevance(it) }
                .thenBy { it.category }
                .thenBy { it.title.lowercase(Locale.ROOT) }
        ).take(30)
        val sourceCounts = hits.groupingBy { it.category }.eachCount()
        val domains = hits.groupingBy {
            runCatching { URL(it.url).host.lowercase(Locale.ROOT).removePrefix("www.") }.getOrDefault("unknown")
        }.eachCount()
        val findings = mutableListOf<Finding>()
        if (hits.isEmpty()) {
            findings += Finding("Публичные упоминания", "Не получены",
                "Поисковая система не вернула пригодные страницы. Возможны сетевые ограничения, блокировка выдачи или отсутствие индексируемых материалов.", "warn")
        } else {
            hits.forEachIndexed { index, hit ->
                val detail = buildString {
                    append(hit.url)
                    if (hit.snippet.isNotBlank()) {
                        append("\nФрагмент: ")
                        append(hit.snippet)
                    }
                    append("\nКатегория запроса: ")
                    append(hit.category)
                }
                findings += Finding("Результат " + (index + 1), hit.title, detail, "info")
            }
        }
        findings += Finding("Покрытие поиска", queries.size.toString() + " поисковых сценария",
            "DuckDuckGo, Wikipedia RU/EN, Wikidata RU/EN, GDELT News, OpenAlex Authors и Crossref Publications; результаты ранжируются по совпадению имени и типу источника, затем дедуплицируются.")
        findings += Finding("Источники данных", sourceCounts.size.toString() + " типов источников",
            sourceCounts.entries.sortedByDescending { it.value }
                .joinToString("\n") { it.key + ": " + it.value + " результатов" }
                .ifBlank { "Источники не вернули результатов." })
        findings += Finding("Разнообразие источников", domains.size.toString() + " доменов",
            domains.entries.sortedByDescending { it.value }.take(15)
                .joinToString("\n") { it.key + ": " + it.value + " стр." }
                .ifBlank { "Домены не определены." })
        findings += Finding("Проверка совпадений", "Требуется ручная верификация",
            "Сверяйте контекст, организацию, область деятельности и даты в независимых источниках. Совпадение имени само по себе не подтверждает личность.", "warn")
        AnalysisResult(cleanName, "Публичные упоминания",
            "Найдено страниц: " + hits.size + "; доменов: " + domains.size + "; сценариев поиска: " + queries.size,
            findings,
            "Поиск выполняется по открытой веб-выдаче DuckDuckGo, Wikipedia RU/EN, Wikidata RU/EN, GDELT News, OpenAlex и Crossref. Результаты дедуплицируются по URL и группируются по доменам. Это список публичных публикаций и упоминаний, а не установление личности. Однофамильцы и разные люди с одинаковым именем могут присутствовать одновременно. Уровень достоверности не повышается только из-за количества ссылок: важно проверить независимость источников и контекст каждой публикации. Запрос имени передаётся поисковой системе. Модуль не ищет домашние адреса, частные контакты, родственников, скрытые аккаунты или местоположение человека.")
    }

    private fun openAlexAuthors(name: String): List<SearchHit> {
        val address = "https://api.openalex.org/authors?search=" + URLEncoder.encode(name, "UTF-8") + "&per-page=8"
        val json = getJson(address) ?: return emptyList()
        val rows = json.optJSONArray("results") ?: return emptyList()
        return (0 until rows.length()).mapNotNull { index ->
            val item = rows.optJSONObject(index) ?: return@mapNotNull null
            val label = item.optString("display_name").takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val wanted = name.lowercase(Locale.ROOT).split(Regex("""\s+""")).filter { it.length > 1 }.toSet()
            val actual = label.lowercase(Locale.ROOT).split(Regex("""[^\p{L}]+""")).filter { it.length > 1 }.toSet()
            if (wanted.isEmpty() || wanted.intersect(actual).size < wanted.size) return@mapNotNull null
            val id = item.optString("id")
            if (!id.startsWith("https://openalex.org/")) return@mapNotNull null
            val works = item.optInt("works_count", 0)
            val orcid = item.optString("orcid")
            val institution = item.optJSONArray("last_known_institutions")?.optJSONObject(0)?.optString("display_name").orEmpty()
            val detail = listOf(if (works > 0) "Публикаций в индексе: $works" else "", institution, orcid).filter { it.isNotBlank() }.joinToString(" · ")
            SearchHit(label, id, detail, "OpenAlex Authors")
        }
    }

    private fun crossrefWorks(name: String): List<SearchHit> {
        val address = "https://api.crossref.org/works?query.author=" + URLEncoder.encode(name, "UTF-8") + "&rows=10&select=title,author,DOI,published,container-title"
        val json = getJson(address) ?: return emptyList()
        val rows = json.optJSONObject("message")?.optJSONArray("items") ?: return emptyList()
        return (0 until rows.length()).mapNotNull { index ->
            val item = rows.optJSONObject(index) ?: return@mapNotNull null
            val title = item.optJSONArray("title")?.optString(0).orEmpty().takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val authors = item.optJSONArray("author") ?: return@mapNotNull null
            val wanted = name.lowercase(Locale.ROOT).split(Regex("""\s+""")).filter { it.length > 1 }.toSet()
            val matchedAuthors = (0 until authors.length()).mapNotNull { authorIndex ->
                val author = authors.optJSONObject(authorIndex) ?: return@mapNotNull null
                val given = author.optString("given")
                val family = author.optString("family")
                val full = listOf(given, family).filter { it.isNotBlank() }.joinToString(" ")
                val tokens = full.lowercase(Locale.ROOT).split(Regex("""[^\p{L}]+""")).filter { it.length > 1 }.toSet()
                if (wanted.isNotEmpty() && tokens.containsAll(wanted)) full else null
            }
            if (matchedAuthors.isEmpty()) return@mapNotNull null
            val doi = item.optString("DOI")
            if (doi.isBlank()) return@mapNotNull null
            val publication = item.optJSONArray("container-title")?.optString(0).orEmpty()
            val year = item.optJSONObject("published")?.optJSONArray("date-parts")?.optJSONArray(0)?.optInt(0)?.takeIf { it > 0 }?.toString().orEmpty()
            SearchHit(title, "https://doi.org/" + doi, listOf(matchedAuthors.joinToString(", "), publication, year).filter { it.isNotBlank() }.joinToString(" · "), "Crossref Publications")
        }
    }
    private fun wikidataPages(name: String, language: String): List<SearchHit> {
        val query = "https://www.wikidata.org/w/api.php?action=wbsearchentities&search=" +
            URLEncoder.encode(name, "UTF-8") + "&language=" + language + "&uselang=" + language + "&format=json&limit=8"
        val json = getJson(query) ?: return emptyList()
        val rows = json.optJSONArray("search") ?: return emptyList()
        return (0 until rows.length()).mapNotNull { index ->
            val item = rows.optJSONObject(index) ?: return@mapNotNull null
            val id = item.optString("id").takeIf { it.matches(Regex("Q[0-9]+")) } ?: return@mapNotNull null
            val label = item.optString("label").ifBlank { id }
            val description = item.optString("description")
            SearchHit(label, "https://www.wikidata.org/wiki/" + id, description, "Wikidata " + language.uppercase(Locale.ROOT))
        }
    }

    private fun gdeltNews(name: String): List<SearchHit> {
        val query = "https://api.gdeltproject.org/api/v2/doc/doc?query=" +
            URLEncoder.encode("\"" + name + "\"", "UTF-8") + "&mode=ArtList&format=json&maxrecords=12&sort=HybridRel"
        val json = getJson(query) ?: return emptyList()
        val rows = json.optJSONArray("articles") ?: return emptyList()
        return (0 until rows.length()).mapNotNull { index ->
            val item = rows.optJSONObject(index) ?: return@mapNotNull null
            val title = item.optString("title").takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val url = item.optString("url")
            if (!url.startsWith("https://")) return@mapNotNull null
            val domain = item.optString("domain")
            val date = item.optString("seendate")
            SearchHit(title, url, listOf(domain, date).filter { it.isNotBlank() }.joinToString(" · "), "GDELT News")
        }
    }
    private fun wikipediaPages(name: String, language: String): List<SearchHit> {
        val query = "https://" + language + ".wikipedia.org/w/api.php?action=query&list=search&srsearch=" +
            URLEncoder.encode(name, "UTF-8") + "&format=json&utf8=1&srlimit=8"
        val json = getJson(query) ?: return emptyList()
        val rows = json.optJSONObject("query")?.optJSONArray("search") ?: return emptyList()
        return (0 until rows.length()).mapNotNull { index ->
            val item = rows.optJSONObject(index) ?: return@mapNotNull null
            val title = item.optString("title").takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val excerpt = stripHtml(item.optString("snippet"))
            val slug = URLEncoder.encode(title.replace(' ', '_'), "UTF-8")
            SearchHit(title, "https://" + language + ".wikipedia.org/wiki/" + slug, excerpt,
                if (language == "ru") "Википедия RU" else "Википедия EN")
        }
    }
    private fun probePublicProfile(address: String, platform: String, handle: String): Pair<String, String> {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull()
            ?: return "Нет ответа" to "Не удалось открыть соединение."
        return try {
            connection.connectTimeout = 7000
            connection.readTimeout = 7000
            connection.instanceFollowRedirects = true
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36")
            connection.setRequestProperty("Accept", "text/html,application/xhtml+xml")
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText().take(500_000) }.orEmpty()
            val normalized = body.lowercase(Locale.ROOT)
            val h = handle.lowercase(Locale.ROOT)
            val explicitProfileMarker = when (platform) {
                "Instagram" -> normalized.contains("\\\"username\\\":\\\"$h\\\"") ||
                    normalized.contains("\\\"profilepage_$h\\\"") ||
                    (normalized.contains("instagram") && normalized.contains("\\\"$h\\\"") && normalized.contains("profile"))
                "TikTok" -> normalized.contains("\\\"uniqueid\\\":\\\"$h\\\"") ||
                    normalized.contains("\\\"unique_id\\\":\\\"$h\\\"")
                "Telegram" -> normalized.contains("tgme_page_username") && normalized.contains(h)
                else -> false
            }
            when {
                code in 200..299 && explicitProfileMarker ->
                    "HTTP $code · есть маркер профиля" to "Ответ страницы содержит маркер, похожий на никнейм. Это сильный кандидат, но проверьте страницу вручную."
                code in 200..299 ->
                    "HTTP $code · сайт ответил" to "Страница доступна, но сайт не отдал надёжный маркер существования именно этого профиля. Возможна общая страница или экран входа."
                code == 404 || code == 410 ->
                    "HTTP $code · страница не найдена" to "Сайт вернул код отсутствия страницы. Некоторые платформы скрывают профили или меняют ответы, поэтому это не окончательное доказательство."
                code == 403 || code == 429 ->
                    "HTTP $code · доступ ограничен" to "Платформа ограничила автоматическую проверку; результат неизвестен, а не «аккаунта нет»."
                code in 300..399 ->
                    "HTTP $code · перенаправление" to "Сайт перенаправил запрос; профиль не подтверждён."
                else -> "HTTP $code · не подтверждено" to "Ответ сайта не позволяет определить существование профиля."
            }
        } catch (e: Exception) {
            "Нет ответа" to "Тайм-аут, блокировка соединения или сетевая ошибка. Это не означает отсутствие аккаунта."
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun searchPublicPages(category: String, query: String): List<SearchHit> =
        searchPublicPages(category, listOf(query))

    private suspend fun searchPublicPages(category: String, queries: List<String>): List<SearchHit> = coroutineScope {
        val jobs = queries.take(4).flatMap { query ->
            listOf(
                async(Dispatchers.IO) { publicSearchGate.withPermit { searchDuckDuckGo(category, query) } },
                async(Dispatchers.IO) { publicSearchGate.withPermit { searchBingRss(category, query) } }
            )
        }
        jobs.awaitAll().flatten()
            .distinctBy { it.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT) }
            .take(60)
    }

    private fun searchDuckDuckGo(category: String, query: String): List<SearchHit> {
        val address = "https://html.duckduckgo.com/html/?q=" + URLEncoder.encode(query, "UTF-8")
        val html = getText(address) ?: return emptyList()
        val output = mutableListOf<SearchHit>()
        val anchor = Regex("""(?is)<a\b([^>]*class=["'][^"']*result__a[^"']*["'][^>]*)>(.*?)</a>""")
        val hrefPattern = Regex("""(?is)href=["']([^"']+)["']""")
        val snippetPattern = Regex("""(?is)class=["'][^"']*result__snippet[^"']*["'][^>]*>(.*?)</(?:a|div)>""")
        anchor.findAll(html).forEach { match ->
            val rawHref = hrefPattern.find(match.groupValues[1])?.groupValues?.get(1) ?: return@forEach
            var target = decodeHtml(rawHref)
            if (target.startsWith("//")) target = "https:" + target
            if (target.contains("uddg=")) {
                target = runCatching {
                    val encoded = target.substringAfter("uddg=").substringBefore("&")
                    URLDecoder.decode(encoded, "UTF-8")
                }.getOrDefault(target)
            }
            if (!target.startsWith("https://") || target.contains("duckduckgo.com")) return@forEach
            val title = stripHtml(match.groupValues[2])
            val tailStart = (match.range.last + 1).coerceAtMost(html.length)
            val tail = html.substring(tailStart, (tailStart + 2200).coerceAtMost(html.length))
            val excerpt = snippetPattern.find(tail)?.groupValues?.get(1)?.let { stripHtml(it) }.orEmpty()
            if (title.isNotBlank()) output += SearchHit(title, target, excerpt, category + " · DuckDuckGo")
        }
        return output
    }

    private fun searchBingRss(category: String, query: String): List<SearchHit> {
        val address = "https://www.bing.com/search?format=rss&q=" + URLEncoder.encode(query, "UTF-8")
        val xml = getText(address) ?: return emptyList()
        val output = mutableListOf<SearchHit>()
        val itemPattern = Regex("""(?is)<item\b[^>]*>(.*?)</item>""")
        fun tag(block: String, name: String): String =
            Regex("""(?is)<$name(?:\s[^>]*)?>(.*?)</$name>""").find(block)?.groupValues?.get(1)
                ?.replace("<![CDATA[", "")?.replace("]]>", "")?.let { stripHtml(it) }.orEmpty()
        itemPattern.findAll(xml).forEach { match ->
            val block = match.groupValues[1]
            val title = tag(block, "title")
            val link = tag(block, "link").trim()
            val description = tag(block, "description")
            if (title.isNotBlank() && link.startsWith("https://") &&
                runCatching { URL(link).host }.getOrDefault("").isNotBlank() &&
                !link.contains("bing.com", ignoreCase = true)) {
                output += SearchHit(title, link, description, category + " · Bing")
            }
        }
        return output
    }

    private fun dataGovDatasetSearch(query: String): List<SearchHit> {
        val address = "https://data.gov.ua/api/3/action/package_search?q=" +
            URLEncoder.encode(query, "UTF-8") + "&rows=8"
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return emptyList()
        return try {
            connection.connectTimeout = 8000
            connection.readTimeout = 10000
            connection.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            connection.setRequestProperty("Accept", "application/json")
            if (connection.responseCode !in 200..299) return emptyList()
            val root = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
            if (!root.optBoolean("success", false)) return emptyList()
            val rows = root.optJSONObject("result")?.optJSONArray("results") ?: return emptyList()
            (0 until rows.length()).mapNotNull { index ->
                val item = rows.optJSONObject(index) ?: return@mapNotNull null
                val title = item.optString("title").ifBlank { item.optString("name") }
                if (title.isBlank()) return@mapNotNull null
                val url = item.optString("url").takeIf { it.startsWith("https://") }
                    ?: "https://data.gov.ua/dataset/" + item.optString("name")
                val notes = item.optString("notes").replace(Regex("<[^>]+>"), " ").replace(Regex("\\s+"), " ").trim().take(500)
                SearchHit(title, url, notes, "data.gov.ua CKAN API")
            }
        } catch (_: Exception) { emptyList() } finally { connection.disconnect() }
    }

    private fun getText(address: String): String? {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return null
        return try {
            connection.connectTimeout = 9000
            connection.readTimeout = 9000
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36")
            connection.setRequestProperty("Accept", "text/html")
            if (connection.responseCode !in 200..299) return null
            connection.inputStream.bufferedReader().use { it.readText() }
        } catch (_: Exception) { null } finally { connection.disconnect() }
    }

    private fun stripHtml(value: String): String = decodeHtml(value.replace(Regex("<[^>]+>"), ""))
        .replace(Regex("\\s+"), " ").trim()

    private fun decodeHtml(value: String): String = value
        .replace("&amp;", "&").replace("&quot;", "\"").replace("&#x27;", "'")
        .replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ")

    private fun email(address: String): AnalysisResult {
        require(address.length <= 254 && address.matches(Regex("^[A-Za-z0-9.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"))) {
            "Введите корректный email в формате name@example.com."
        }
        val host = address.substringAfter("@").lowercase(Locale.ROOT)
        val findings = mutableListOf<Finding>()
        findings += Finding("Формат", "Корректный синтаксис", "Адрес прошёл базовую проверку формата.", "good")
        val mx = dns(host, "MX")
        if (mx.isNotEmpty()) findings += Finding("MX-записи", "Найдены", mx.joinToString("\n"), "good")
        else findings += Finding("MX-записи", "Не обнаружены", "У домена не найден MX-ответ через публичный DNS-over-HTTPS.", "warn")
        val a = dns(host, "A")
        findings += Finding("DNS A", if (a.isEmpty()) "Нет ответа" else "Найдены", a.ifEmpty { listOf("A-записи не получены") }.joinToString("\n"), if (a.isEmpty()) "warn" else "info")
        val spf = dns(host, "TXT").filter { it.contains("v=spf1", true) }
        findings += Finding("SPF", if (spf.isEmpty()) "Не обнаружена" else "Найдена",
            spf.ifEmpty { listOf("SPF TXT-запись не получена.") }.joinToString("\n"), if (spf.isEmpty()) "warn" else "good")
        val dmarc = dns("_dmarc." + host, "TXT").filter { it.contains("v=DMARC1", true) }
        findings += Finding("DMARC", if (dmarc.isEmpty()) "Не обнаружена" else "Найдена",
            dmarc.ifEmpty { listOf("DMARC TXT-запись не получена.") }.joinToString("\n"), if (dmarc.isEmpty()) "warn" else "good")
        return AnalysisResult(address, "Email OSINT", "Проверен формат, MX, SPF и DMARC домена $host", findings,
            "Проверка не подтверждает существование почтового ящика и не отправляет письмо. MX-записи показывают, что домен настроен принимать почту; это не гарантирует доставку или существование конкретного адреса.")
    }

    private fun domain(raw: String): AnalysisResult {
        val host = raw.removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":").trim('.').lowercase(Locale.ROOT)
        require(host.length <= 253 && host.contains(".") && host.matches(Regex("(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")) && !host.contains("..")) {
            "Введите домен, например example.com."
        }
        val findings = mutableListOf<Finding>()
        val a = dns(host, "A")
        val aaaa = dns(host, "AAAA")
        val mx = dns(host, "MX")
        val ns = dns(host, "NS")
        val txt = dns(host, "TXT")
        val caa = dns(host, "CAA")
        findings += Finding("IPv4 (A)", if (a.isEmpty()) "Не найдены" else a.joinToString(), "Публичные DNS-ответы Cloudflare.", if (a.isEmpty()) "warn" else "good")
        findings += Finding("IPv6 (AAAA)", if (aaaa.isEmpty()) "Не найдены" else aaaa.joinToString(), "Публичные DNS-ответы Cloudflare.")
        findings += Finding("Почтовые серверы (MX)", if (mx.isEmpty()) "Не найдены" else mx.joinToString(), "Публичные DNS-ответы Cloudflare.")
        findings += Finding("NS-серверы", if (ns.isEmpty()) "Не найдены" else ns.joinToString(), "Публичные DNS-ответы Cloudflare.")
        findings += Finding("TXT-записи", if (txt.isEmpty()) "Не найдены" else txt.size.toString() + " записей",
            txt.take(20).joinToString("\n").ifBlank { "TXT-записи не получены." })
        findings += Finding("CAA-записи", if (caa.isEmpty()) "Не найдены" else caa.size.toString() + " записей",
            caa.joinToString("\n").ifBlank { "CAA-записи не получены." })
        val rdap = getJson("https://rdap.org/domain/${URLEncoder.encode(host, "UTF-8")}")
        if (rdap != null) {
            val registrar = runCatching { rdap.getJSONArray("entities").optJSONObject(0)?.optString("handle").orEmpty() }.getOrDefault("")
            val events = runCatching { rdap.getJSONArray("events") }.getOrNull()
            val eventText = if (events != null) (0 until events.length()).mapNotNull { i ->
                val e = events.optJSONObject(i); val action = e?.optString("eventAction").orEmpty(); val date = e?.optString("eventDate").orEmpty()
                if (action.isNotBlank()) "$action: $date" else null
            }.joinToString("\n") else ""
            findings += Finding("RDAP", "Регистрационные данные получены", listOf(registrar, eventText).filter { it.isNotBlank() }.joinToString("\n").ifBlank { "Ответ RDAP получен." }, "good")
        } else findings += Finding("RDAP", "Нет данных", "Регистратор не вернул доступный RDAP-ответ.", "warn")
        val certQuery = "https://crt.sh/?q=%25." + URLEncoder.encode(host, "UTF-8") + "&output=json"
        val certificates = getJsonArray(certQuery)
        if (certificates != null) {
            val names = linkedSetOf<String>()
            for (i in 0 until certificates.length()) {
                val row = certificates.optJSONObject(i) ?: continue
                val rawNames = row.optString("name_value")
                rawNames.split("\n", "\r").forEach { candidate ->
                    val normalized = candidate.trim().removePrefix("*.").lowercase(Locale.ROOT)
                    if (normalized == host || normalized.endsWith("." + host)) names += normalized
                }
            }
            findings += Finding("Certificate Transparency", names.size.toString() + " публичных имён",
                names.take(50).joinToString("\n").ifBlank { "В доступном ответе не обнаружены имена поддоменов." },
                if (names.isEmpty()) "info" else "good")
        } else findings += Finding("Certificate Transparency", "Нет ответа",
            "Журнал crt.sh недоступен или не вернул JSON. Это не означает отсутствие сертификатов.", "warn")
        return AnalysisResult(host, "Domain OSINT", "Собраны DNS, RDAP и Certificate Transparency сведения по $host", findings,
            "DNS показывает текущую публичную конфигурацию домена, а RDAP — доступные регистрационные сведения. Отсутствие ответа не означает, что домен не существует: возможны ограничения DNS, приватность регистратора или временная недоступность источника.")
    }

    private fun dns(host: String, type: String): List<String> {
        val json = getJson("https://cloudflare-dns.com/dns-query?name=${URLEncoder.encode(host, "UTF-8")}&type=$type", "application/dns-json") ?: return emptyList()
        val answers = json.optJSONArray("Answer") ?: return emptyList()
        return (0 until answers.length()).mapNotNull { answers.optJSONObject(it)?.optString("data")?.takeIf { v -> v.isNotBlank() } }.distinct()
    }

    private fun getJson(address: String, accept: String = "application/json"): JSONObject? {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return null
        return try {
            connection.connectTimeout = 7000
            connection.readTimeout = 7000
            connection.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            connection.setRequestProperty("Accept", accept)
            if (connection.responseCode !in 200..299) return null
            JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
        } catch (_: Exception) { null } finally { connection.disconnect() }
    }

    private fun getJsonArray(address: String): org.json.JSONArray? {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return null
        return try {
            connection.connectTimeout = 9000
            connection.readTimeout = 12000
            connection.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            connection.setRequestProperty("Accept", "application/json")
            if (connection.responseCode !in 200..299) return null
            org.json.JSONArray(connection.inputStream.bufferedReader().use { it.readText() })
        } catch (_: Exception) { null } finally { connection.disconnect() }
    }

    private fun request(address: String): Int {
        val connection = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return -1
        return try {
            connection.connectTimeout = 6000
            connection.readTimeout = 6000
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36")
            connection.responseCode
        } catch (_: Exception) { -1 } finally { connection.disconnect() }
    }
}
