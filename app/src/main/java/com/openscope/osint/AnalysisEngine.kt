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
    val level: String = "info"
)

data class AnalysisResult(
    val subject: String,
    val module: String,
    val summary: String,
    val findings: List<Finding>,
    val explanation: String
)

object AnalysisEngine {
    suspend fun run(type: String, raw: String, context: Context): AnalysisResult = withContext(Dispatchers.IO) {
        val value = raw.trim()
        when (type) {
            "username" -> username(value, context)
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
        AnalysisResult(name, "Username OSINT · WhatsMyName", "Проверено площадок: " + eligible.size + "; возможных совпадений: " + found.size + "; неоднозначных ответов: " + uncertain, findings,
            "Движок использует открытый набор правил WhatsMyName, включённый в APK при сборке. Совпадение — кандидат публичного профиля, а не доказательство владения аккаунтом или того, что профили принадлежат одному человеку. Сайты могут менять ответы; отсутствие результата ничего не доказывает. Используются только публичные HTTPS GET-проверки; POST, авторизация, CAPTCHA и NSFW-источники отключены.")
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
        val pages = webPages + encyclopediaPages + knowledgePages + newsPages
        val unique = linkedMapOf<String, SearchHit>()
        pages.forEach { hit ->
            val key = hit.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT)
            if (key.startsWith("https://") && !unique.containsKey(key)) unique[key] = hit
        }
        val hits = unique.values.take(30)
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
            "DuckDuckGo, Wikipedia RU/EN, Wikidata RU/EN и GDELT News; результаты объединяются и дедуплицируются.")
        findings += Finding("Разнообразие источников", domains.size.toString() + " доменов",
            domains.entries.sortedByDescending { it.value }.take(15)
                .joinToString("\n") { it.key + ": " + it.value + " стр." }
                .ifBlank { "Домены не определены." })
        findings += Finding("Проверка совпадений", "Требуется ручная верификация",
            "Сверяйте контекст, организацию, область деятельности и даты в независимых источниках. Совпадение имени само по себе не подтверждает личность.", "warn")
        AnalysisResult(cleanName, "Публичные упоминания",
            "Найдено страниц: " + hits.size + "; доменов: " + domains.size + "; сценариев поиска: " + queries.size,
            findings,
            "Поиск выполняется по открытой веб-выдаче DuckDuckGo, Wikipedia RU/EN, Wikidata RU/EN и новостному индексу GDELT. Результаты дедуплицируются по URL и группируются по доменам. Это список публичных публикаций и упоминаний, а не установление личности. Однофамильцы и разные люди с одинаковым именем могут присутствовать одновременно. Уровень достоверности не повышается только из-за количества ссылок: важно проверить независимость источников и контекст каждой публикации. Запрос имени передаётся поисковой системе. Модуль не ищет домашние адреса, частные контакты, родственников, скрытые аккаунты или местоположение человека.")
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
    private suspend fun searchPublicPages(category: String, query: String): List<SearchHit> {
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
                    URLDecoder.decode(target.substringAfter("uddg=").substringBefore("&"), "UTF-8")
                }.getOrDefault(target)
            }
            if (!target.startsWith("https://")) return@forEach
            if (target.contains("duckduckgo.com")) return@forEach
            val title = stripHtml(match.groupValues[2])
            val tailStart = (match.range.last + 1).coerceAtMost(html.length)
            val tail = html.substring(tailStart, (tailStart + 2200).coerceAtMost(html.length))
            val excerpt = snippetPattern.find(tail)?.groupValues?.get(1)?.let { stripHtml(it) }.orEmpty()
            if (title.isNotBlank()) output += SearchHit(title, target, excerpt, category)
        }
        return output
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
