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

    private data class SearchHit(val title: String, val url: String, val snippet: String, val queryLabel: String)

    private suspend fun person(name: String): AnalysisResult = coroutineScope {
        require(name.length in 3..80 && name.matches(Regex("[\\\\p{L}][\\\\p{L} .’'\\\\-]{1,78}[\\\\p{L}]"))) {
            "Введите имя и фамилию (3–80 символов)."
        }
        // Search only public, non-sensitive mentions. Do not query addresses, private contacts,
        // relatives, whereabouts, or data-broker sources.
        val searches = listOf(
            "exact" to "\\"$name\\"",
            "professional" to "\\"$name\\" (профессиональный профиль OR публикация OR конференция)",
            "publications" to "\\"$name\\" (автор OR исследование OR статья OR ORCID)",
            "news" to "\\"$name\\" (новости OR интервью OR событие)"
        )
        val batches = searches.map { (label, query) ->
            async(Dispatchers.IO) { searchPublicMentions(query, label) }
        }.awaitAll()
        val all = batches.flatten()
        val unique = linkedMapOf<String, SearchHit>()
        all.forEach { hit ->
            val canonical = hit.url.substringBefore("#").trimEnd('/').lowercase(Locale.ROOT)
            if (canonical.startsWith("https://") && canonical !in unique) unique[canonical] = hit
        }
        val hits = unique.values.take(24)
        val byDomain = hits.groupingBy { runCatching { URL(it.url).host.removePrefix("www.") }.getOrDefault("источник") }.eachCount()
        val findings = mutableListOf<Finding>()
        if (hits.isEmpty()) {
            findings += Finding("Публичные упоминания", "Результаты не получены",
                "Поисковая система не вернула доступные страницы. Это не доказывает отсутствие информации; возможны ограничения или блокировка выдачи.", "warn")
        } else {
            hits.forEachIndexed { index, hit ->
                val details = buildString {
                    append(hit.url)
                    if (hit.snippet.isNotBlank()) append("\\n").append(hit.snippet)
                    append("\\nТип запроса: ").append(hit.queryLabel)
                }
                findings += Finding("Открытая публикация " + (index + 1), hit.title, details, "info")
            }
        }
        findings += Finding("Источники", byDomain.size.toString() + " доменов",
            byDomain.entries.sortedByDescending { it.value }.take(12).joinToString("\\n") { "${it.key}: ${it.value}" }.ifBlank { "Домены не определены." })
        findings += Finding("Методика", searches.size.toString() + " варианта публичного поиска",
            "Точное имя, профессиональные публичные страницы, публикации и новостные упоминания. Результаты дедуплицированы по URL.")
        AnalysisResult(name, "Поиск публичных упоминаний",
            "Получено страниц: ${hits.size}; независимых доменов: ${byDomain.size}; поисковых вариантов: ${searches.size}. Личность не устанавливается.",
            findings,
            "Поиск расширен с одного точного запроса до нескольких тематических вариантов. Результаты содержат заголовок, фрагмент, домен и исходную ссылку. Это лишь публичные веб-упоминания: однофамильцы, тёзки и страницы о разных людях могут смешиваться. Совпадение имени, фотографии или домена не доказывает, что страницы относятся к одному человеку. Для проверки используйте контекст публикации и независимые источники. Модуль намеренно не ищет домашние адреса, частные контакты, родственников, местоположение или закрытые сведения. Имя передаётся поисковой системе DuckDuckGo.")
    }

    private suspend fun searchPublicMentions(query: String, label: String): List<SearchHit> {
        val address = "https://html.duckduckgo.com/html/?q=" + URLEncoder.encode(query, "UTF-8")
        val html = getText(address) ?: return emptyList()
        val resultBlocks = Regex("""(?is)<div[^>]+class=["'][^"']*result[^"']*["'][^>]*>(.*?)</div>\\s*(?=<div[^>]+class=["'][^"']*result|</div>)""")
        val blocks = resultBlocks.findAll(html).map { it.groupValues[1] }.toList()
        val source = if (blocks.isNotEmpty()) blocks else listOf(html)
        val output = mutableListOf<SearchHit>()
        val anchor = Regex("""(?is)<a\\b([^>]*class=["'][^"']*result__a[^"']*["'][^>]*)>(.*?)</a>""")
        val href = Regex("""(?is)href=["']([^"']+)["']""")
        val snippet = Regex("""(?is)<(?:a|div)[^>]*class=["'][^"']*result__snippet[^"']*["'][^>]*>(.*?)</(?:a|div)>""")
        source.forEach { block ->
            val match = anchor.find(block) ?: return@forEach
            val rawHref = href.find(match.groupValues[1])?.groupValues?.get(1) ?: return@forEach
            var target = decodeHtml(rawHref)
            if (target.startsWith("//")) target = "https:$target"
            if (target.contains("uddg=")) {
                target = runCatching {
                    URLDecoder.decode(target.substringAfter("uddg=").substringBefore("&"), "UTF-8")
                }.getOrDefault(target)
            }
            if (!target.startsWith("https://")) return@forEach
            val title = stripHtml(match.groupValues[2])
            val excerpt = snippet.find(block)?.groupValues?.get(1)?.let { stripHtml(it) }.orEmpty()
            if (title.isNotBlank() && !target.contains("duckduckgo.com")) {
                output += SearchHit(title, target, excerpt, label)
            }
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
