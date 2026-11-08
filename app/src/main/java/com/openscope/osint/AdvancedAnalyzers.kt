package com.openscope.osint

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object AdvancedAnalyzers {
    suspend fun ip(raw: String): AnalysisResult = withContext(Dispatchers.IO) {
        val address = raw.trim()
        val parsed = runCatching { java.net.InetAddress.getByName(address) }.getOrNull()
        require(parsed != null && (address.contains(".") || address.contains(":"))) { "Введите IPv4 или IPv6 адрес." }
        require(!parsed.isLoopbackAddress && !parsed.isAnyLocalAddress && !parsed.isLinkLocalAddress && !parsed.isSiteLocalAddress) { "Нужен публичный IP-адрес." }
        val findings = mutableListOf<Finding>()
        findings += Finding("IP", parsed.hostAddress ?: address, "Нормализованный адрес.", "good")
        val data = json("https://ipwho.is/" + address)
        if (data != null && data.optBoolean("success", false)) {
            val connection = data.optJSONObject("connection")
            val timezone = data.optJSONObject("timezone")
            listOf(
                "Страна" to data.optString("country"),
                "Регион" to data.optString("region"),
                "Город" to data.optString("city"),
                "Провайдер" to (connection?.optString("isp") ?: ""),
                "Организация" to (connection?.optString("org") ?: ""),
                "ASN" to (connection?.optString("asn") ?: ""),
                "Часовой пояс" to (timezone?.optString("id") ?: "")
            ).forEach { pair -> if (pair.second.isNotBlank() && pair.second != "null") findings += Finding(pair.first, pair.second, "Ответ публичного IP-справочника.") }
            val lat = data.optDouble("latitude", Double.NaN)
            val lon = data.optDouble("longitude", Double.NaN)
            if (!lat.isNaN() && !lon.isNaN()) findings += Finding("Приблизительные координаты", lat.toString() + ", " + lon, "Это геолокация IP-узла, не точный адрес человека.", "warn")
        } else findings += Finding("Геоданные", "Нет ответа", "IP-справочник недоступен или адрес не поддерживается.", "warn")
        AnalysisResult(address, "IP OSINT", "Публичные сетевые сведения по IP", findings,
            "Геолокация IP приблизительна и обычно указывает на город или узел провайдера, а не местоположение человека. VPN, мобильная сеть и прокси меняют результат. Для геоинформации IP передаётся сервису ipwho.is.")
    }

    suspend fun url(raw: String): AnalysisResult = withContext(Dispatchers.IO) {
        val input = if (raw.startsWith("http://") || raw.startsWith("https://")) raw else "https://" + raw
        val parsed = runCatching { URL(input) }.getOrNull()
        require(parsed != null && parsed.protocol in listOf("http", "https") && parsed.host.contains(".")) { "Введите корректный URL или домен." }
        val findings = mutableListOf<Finding>()
        findings += Finding("Хост", parsed.host, "Домен из URL.", "good")
        findings += Finding("Протокол", parsed.protocol.uppercase(), "Схема URL.")
        findings += Finding("Порт", if (parsed.port == -1) "Стандартный" else parsed.port.toString(), "Порт соединения.")
        val status = runCatching {
            val c = URL(input).openConnection() as HttpURLConnection
            c.connectTimeout = 6000
            c.readTimeout = 6000
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            val code = c.responseCode
            c.disconnect()
            code
        }.getOrDefault(-1)
        findings += Finding("HTTP", if (status < 0) "Нет ответа" else status.toString(), "Код ответа не является оценкой безопасности сайта.", if (status in 200..399) "good" else "warn")
        AnalysisResult(input, "URL Analysis", "Проверены структура URL и доступность сервера", findings,
            "Это не антивирус и не проверка репутации URL. Код 200 не доказывает безопасность сайта. Не открывайте подозрительные ссылки только на основании этого результата.")
    }

    private fun json(address: String): JSONObject? {
        val c = runCatching { URL(address).openConnection() as HttpURLConnection }.getOrNull() ?: return null
        return try {
            c.connectTimeout = 7000
            c.readTimeout = 7000
            c.setRequestProperty("User-Agent", "OpenScope-OSINT-Android/1.0")
            if (c.responseCode !in 200..299) return null
            JSONObject(c.inputStream.bufferedReader().use { it.readText() })
        } catch (_: Exception) { null } finally { c.disconnect() }
    }
}
