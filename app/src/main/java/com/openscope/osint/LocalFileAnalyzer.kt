package com.openscope.osint

import android.content.Context
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

object LocalFileAnalyzer {
    suspend fun image(context: Context, uri: Uri): AnalysisResult = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val name = resolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        } ?: "Выбранное изображение"
        val mime = resolver.getType(uri) ?: "не определён"
        val findings = mutableListOf<Finding>()
        findings += Finding("Файл", name, "MIME: $mime", "good")
        resolver.openInputStream(uri)?.use { input ->
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
            findings += Finding("SHA-256", digest.digest().joinToString("") { "%02x".format(it) }, "Криптографический отпечаток выбранного файла.", "good")
        } ?: findings.add(Finding("SHA-256", "Не рассчитан", "Не удалось прочитать файл.", "warn"))
        val exif = resolver.openInputStream(uri)?.use { ExifInterface(it) }
        if (exif != null) {
            val tags = listOf(
                "Дата съёмки" to ExifInterface.TAG_DATETIME_ORIGINAL,
                "Производитель" to ExifInterface.TAG_MAKE,
                "Модель камеры" to ExifInterface.TAG_MODEL,
                "ПО" to ExifInterface.TAG_SOFTWARE,
                "Ориентация" to ExifInterface.TAG_ORIENTATION,
                "Фокусное расстояние" to ExifInterface.TAG_FOCAL_LENGTH,
                "ISO" to ExifInterface.TAG_ISO_SPEED_RATINGS,
                "Экспозиция" to ExifInterface.TAG_EXPOSURE_TIME
            )
            tags.forEach { (label, tag) ->
                val value = exif.getAttribute(tag)
                if (!value.isNullOrBlank()) findings += Finding(label, value, "Значение из EXIF-метаданных.", "info")
            }
            val lat = exif.latLong
            if (lat != null) findings += Finding("GPS", "${lat[0]}, ${lat[1]}", "Координаты, записанные в метаданные изображения. Это может раскрывать место съёмки.", "warn")
            else findings += Finding("GPS", "Координаты не найдены", "В доступных EXIF-метаданных нет GPS-позиции.")
        } else findings += Finding("EXIF", "Метаданные отсутствуют или недоступны", "Формат может не содержать EXIF или файл не удалось разобрать.", "warn")
        return@withContext AnalysisResult(name, "Image & Metadata", "Локально изучены метаданные и рассчитан SHA-256", findings,
            "EXIF может содержать дату, модель устройства, параметры камеры и GPS-координаты. Социальные сети часто удаляют часть метаданных. Отсутствие GPS не доказывает, что фото сделано в другом месте. Сам файл не отправляется на сервер.")
    }
}
