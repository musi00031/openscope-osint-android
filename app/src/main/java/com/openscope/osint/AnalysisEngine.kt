package com.openscope.osint

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
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
    suspend fun run(type: String, raw: String): AnalysisResult = withContext(Dispatchers.IO) {
        val value = raw.trim()
        when (type) {
            "username" -> username(value)
            "person" -> person(value)
            "email" -> email(value)
            else -> domain(value)
        }
    }

    private fun username(name: String): AnalysisResult {
        require(name.matches(Regex("[A-Za-z0-9._-]{2,30}"))) { "Никнейм: используйте 2–30 символов: латиница, цифры, точка, дефис или _." }
        val sites = listOf(
            "GitHub" to "https://github.com/$name",
            "Reddit" to "https://www.reddit.com/user/$name/",
            "GitLab" to "https://gitlab.com/$name",
            "Pinterest" to "https://www.pinterest.com/$name/",
            "Medium" to "https://medium.com/@$name",
            "TikTok" to "https://www.tiktok.com/@$name",
            "Instagram" to "https://www.instagram.com/$name/",
            "X" to "https://x.com/$name",
            "Twitch" to "https://www.twitch.tv/$name",
            "YouTube" to "https://www.youtube.com/@$name",
            "Telegram" to "https://t.me/$name",
            "Steam" to "https://steamcommunity.com/id/$name",
            "SoundCloud" to "https://soundcloud.com/$name",
            "DEV" to "https://dev.to/$name",
            "Keybase" to "https://keybase.io/$name",
            "Hacker News" to "https://news.ycombinator.com/user?id=$name",
            "About.me" to "https://about.me/$name"
        )
        val findings = sites.map { (site, address) ->
            val status = request(address)
            when {
                status == 200 -> Finding(site, "Профиль отвечает (HTTP 200)", address, "good")
                status == 404 -> Finding(site, "Профиль не найден (HTTP 404)", address, "info")
                status == 403 || status == 429 -> Finding(site, "Источник ограничил проверку (HTTP $status)", address, "warn")
                status in 300..399 -> Finding(site, "Перенаправление (HTTP $status)", address, "warn")
                status < 0 -> Finding(site, "Не удалось проверить", "Сетевая ошибка или тайм-аут", "warn")
                else -> Finding(site, "Неоднозначный ответ (HTTP $status)", address, "warn")
            }
        }
        val found = findings.count { it.level == "good" }
        val uncertain = findings.count { it.level == "warn" }
        return AnalysisResult(name, "Username OSINT", "Проверено источников: ${sites.size}; ответили: $found; неоднозначно: $uncertain", findings,
            "Проверены только публичные страницы профилей. HTTP 200 не доказывает, что аккаунт принадлежит одному человеку: некоторые сайты показывают заглушки или требуют авторизацию. Совпадение никнейма — лишь зацепка, а не подтверждение личности.")
    }

    private fun person(name: String): AnalysisResult {
        require(name.length in 3..80 && name.matches(Regex("[\\p{L}][\\p{L} .’'\\-]{1,78}[\\p{L}]"))) {
            "Введите имя и фамилию (3–80 символов)."
        }
        val query = "\"" + name.trim() + "\""
        val address = "https://html.duckduckgo.com/html/?q=" + URLEncoder.encode(query, "UTF-8")
        val html = getText(address)
        val links = mutableListOf<Pair<String, String>>()
        if (html != null) {
            val pattern = Regex("""<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>""", RegexOption.DOT_MATCHES_ALL)
            pattern.findAll(html).take(8).forEach { match ->
                val href = decodeHtml(match.groupValues[1])
                val title = stripHtml(match.groupValues[2])
                if (href.startsWith("http") && title.isNotBlank() && !href.contains("duckduckgo.com")) links += title to href
            }
        }
        val findings = mutableListOf<Finding>()
        if (links.isEmpty()) findings += Finding("Публичный веб-поиск", "Результаты не получены", "Поисковик не вернул доступные результаты. Попробуйте уточнить написание имени или повторить позже.", "warn")
        else links.forEachIndexed { index, item -> findings += Finding("Публичное упоминание " + (index + 1), item.first, item.second, "info") }
        findings += Finding("Метод", "Поиск по точному имени", "Источник: DuckDuckGo HTML. Выдача может быть неполной и содержать однофамильцев.")
        return AnalysisResult(name, "Поиск человека", "Найдено публичных веб-результатов: " + links.size + ". Это зацепки, а не установленная личность.", findings,
            "Совпадение имени не подтверждает, что найденные страницы относятся к одному человеку. Нужны независимые совпадения из открытых источников. Модуль не ищет домашние адреса, закрытые контакты, пароли или местоположение человека. Запрос имени передаётся поисковой системе DuckDuckGo.")
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
        return AnalysisResult(address, "Email OSINT", "Проверен формат и публичная DNS-конфигурация домена $host", findings,
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
        findings += Finding("IPv4 (A)", if (a.isEmpty()) "Не найдены" else a.joinToString(), "Публичные DNS-ответы Cloudflare.", if (a.isEmpty()) "warn" else "good")
        findings += Finding("IPv6 (AAAA)", if (aaaa.isEmpty()) "Не найдены" else aaaa.joinToString(), "Публичные DNS-ответы Cloudflare.")
        findings += Finding("Почтовые серверы (MX)", if (mx.isEmpty()) "Не найдены" else mx.joinToString(), "Публичные DNS-ответы Cloudflare.")
        findings += Finding("NS-серверы", if (ns.isEmpty()) "Не найдены" else ns.joinToString(), "Публичные DNS-ответы Cloudflare.")
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
        return AnalysisResult(host, "Domain OSINT", "Собраны публичные DNS- и RDAP-сведения по $host", findings,
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
