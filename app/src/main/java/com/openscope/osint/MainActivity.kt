package com.openscope.osint

import android.os.Bundle
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.geometry.Offset
import androidx.compose.animation.core.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Bg = Color(0xFF050608)
private val Panel = Color(0xFF111419)
private val Accent = Color(0xFFC5CBD3)
private val Silver = Color(0xFFE7EAEE)
private val Muted = Color(0xFF89919B)

data class OsintModule(val id: String, val title: String, val description: String, val category: String, val state: String)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { OpenScopeApp() }
    }
}

@Composable
fun OpenScopeApp() {
    var tab by remember { mutableStateOf("Главная") }
    var query by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf("username") }
    var status by remember { mutableStateOf("Готов к исследованию") }
    var loading by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<AnalysisResult?>(null) }
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("openscope_local", android.content.Context.MODE_PRIVATE) }
    var history by remember { mutableStateOf(prefs.getString("history", "")?.split("\\n")?.filter { it.isNotBlank() } ?: emptyList()) }
    val scope = rememberCoroutineScope()
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            loading = true
            status = "Локальный анализ изображения…"
            scope.launch {
                try {
                    val analysis = LocalFileAnalyzer.image(context, uri)
                    result = analysis
                    val stamp = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date())
                    history = listOf("$stamp • ${analysis.module} • ${analysis.subject}") + history
                    prefs.edit().putString("history", history.joinToString("\\n")).apply()
                    status = "Анализ изображения завершён"
                } catch (e: Exception) { status = e.message ?: "Не удалось прочитать файл" }
                finally { loading = false }
            }
        }
    }
    val modules = remember {
        listOf(
            OsintModule("username", "Username OSINT", "Проверка 17 публичных профилей и площадок", "Идентификаторы", "Работает"),
            OsintModule("person", "Поиск человека", "Поиск публичных упоминаний по имени и фамилии", "Идентификаторы", "Работает"),
            OsintModule("email", "Email OSINT", "Синтаксис адреса и DNS/MX домена почты", "Идентификаторы", "Работает"),
            OsintModule("domain", "Domain OSINT", "DNS A/AAAA/MX/NS/TXT/CAA и RDAP", "Инфраструктура", "Работает"),
            OsintModule("ip", "IP OSINT", "Публичная геолокация, ASN и провайдер", "Инфраструктура", "Работает"),
            OsintModule("url", "URL Analysis", "Разбор URL и HTTP-доступность", "Инфраструктура", "Работает"),
            OsintModule("image", "Image & Metadata", "Локальный EXIF, GPS и SHA-256", "Медиа", "Работает"),
            OsintModule("report", "Отчёты", "Просмотр результатов текущего сеанса", "Аналитика", "Базовый")
        )
    }
    MaterialTheme(colorScheme = darkColorScheme(
        background = Bg, surface = Panel, primary = Accent, onPrimary = Color.White,
        onBackground = Silver, onSurface = Silver, secondary = Muted
    )) {
        Scaffold(containerColor = Bg, bottomBar = {
            NavigationBar(containerColor = Panel) {
                listOf("Главная", "Модули", "История").forEach { item ->
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { tab = item },
                        icon = {
                            Icon(when(item) {
                                "Главная" -> Icons.Default.Dashboard
                                "Модули" -> Icons.Default.Hub
                                else -> Icons.Default.History
                            }, contentDescription = null)
                        },
                        label = { Text(item) },
                        colors = NavigationBarItemDefaults.colors(selectedIconColor = Accent, indicatorColor = Color(0xFF382326), selectedTextColor = Silver, unselectedTextColor = Muted)
                    )
                }
            }
        }) { padding ->
            when(tab) {
                "Главная" -> HomeScreen(
                    padding, query, { query = it }, selected, { selected = it },
                    modules, status, loading, result,
                    onPickImage = { imagePicker.launch(arrayOf("image/*")) },
                    onShare = { analysis ->
                        val report = buildString {
                            appendLine("OPENSCOPE OSINT — РАСШИРЕННЫЙ ОТЧЁТ")
                            appendLine("Дата формирования: " + SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.getDefault()).format(Date()))
                            appendLine("Модуль: " + analysis.module)
                            appendLine("Объект исследования: " + analysis.subject)
                            appendLine()
                            appendLine("1. СВОДКА")
                            appendLine(analysis.summary)
                            appendLine()
                            appendLine("2. НАЙДЕННЫЕ ДАННЫЕ И ИСТОЧНИКИ")
                            analysis.findings.forEachIndexed { index, finding ->
                                appendLine((index + 1).toString() + ". " + finding.title)
                                appendLine("   Результат: " + finding.value)
                                appendLine("   Детали / источник: " + finding.detail)
                                appendLine("   Уровень сигнала: " + finding.level)
                                appendLine()
                            }
                            appendLine("3. АНАЛИТИЧЕСКОЕ ПОЯСНЕНИЕ")
                            appendLine(analysis.explanation)
                            appendLine()
                            appendLine("4. МЕТОДОЛОГИЯ И ОГРАНИЧЕНИЯ")
                            appendLine("Собраны только доступные публичные ответы выбранных источников. Отсутствие результата не доказывает отсутствие сведений. Совпадения требуют независимой проверки; автоматический поиск не устанавливает личность.")
                            appendLine("5. ПРИВАТНОСТЬ")
                            appendLine("Внешние источники получают поисковые запросы и проверяемые идентификаторы. Не используйте результаты для преследования, доксинга или иных неправомерных действий.")
                        }
                        val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "OpenScope OSINT — ${analysis.subject}"); putExtra(Intent.EXTRA_TEXT, report) }
                        context.startActivity(Intent.createChooser(send, "Экспорт отчёта"))
                    },
                    onRun = {
                        val input = query.trim()
                        if (input.isBlank()) status = "Введите объект исследования"
                        else {
                            loading = true
                            result = null
                            status = "Анализ выполняется…"
                            scope.launch {
                                try {
                                    val analysis = AnalysisEngine.run(selected, input, context)
                                    result = analysis
                                    val stamp = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date())
                                    history = listOf("$stamp • ${analysis.module} • ${analysis.subject}") + history
                                    prefs.edit().putString("history", history.joinToString("\\n")).apply()
                                    status = "Анализ завершён"
                                } catch (e: Exception) {
                                    status = e.message ?: "Не удалось выполнить анализ"
                                } finally { loading = false }
                            }
                        }
                    }
                )
                "Модули" -> ModulesScreen(padding, modules)
                else -> HistoryScreen(padding, history)
            }
        }
    }
}

@Composable
fun HomeScreen(
    padding: PaddingValues, query: String, onQuery: (String) -> Unit,
    selected: String, onSelected: (String) -> Unit, modules: List<OsintModule>,
    status: String, loading: Boolean, result: AnalysisResult?, onPickImage: () -> Unit, onShare: (AnalysisResult) -> Unit, onRun: () -> Unit
) {
    val flow by rememberInfiniteTransition(label = "silverFlow").animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(6500, easing = LinearEasing), repeatMode = RepeatMode.Reverse),
        label = "silverFlowOffset"
    )
    val shimmer = Brush.linearGradient(
        colors = listOf(Color(0xFF050608), Color(0xFF171C22), Color(0xFF090B0F), Color(0xFF242A32), Color(0xFF050608)),
        start = Offset(flow * 850f, 0f), end = Offset(950f - flow * 500f, 1800f)
    )
    LazyColumn(Modifier.fillMaxSize().background(shimmer).padding(padding).padding(horizontal = 18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Spacer(Modifier.height(12.dp))
            Text("OPENSCOPE", color = Silver, fontSize = 25.sp, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
            Text("OSINT WORKSPACE  •  ANDROID", color = Muted, fontSize = 11.sp, letterSpacing = 1.4.sp)
        }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Новое исследование", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                    Text("Пассивный анализ публичных источников. Результаты обрабатываются на устройстве; для запросов к открытым источникам нужен интернет.", color = Muted, fontSize = 12.sp)
                    OutlinedTextField(value = query, onValueChange = onQuery, modifier = Modifier.fillMaxWidth(), label = { Text("Объект исследования") }, singleLine = true)
                    Text("Тип исследования", color = Muted, fontSize = 12.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected == "username", { onSelected("username") }, label = { Text("Никнейм") })
                        FilterChip(selected == "email", { onSelected("email") }, label = { Text("Email") })
                        FilterChip(selected == "domain", { onSelected("domain") }, label = { Text("Домен") })
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected == "ip", { onSelected("ip") }, label = { Text("IP") })
                        FilterChip(selected == "url", { onSelected("url") }, label = { Text("URL") })
                        FilterChip(selected == "person", { onSelected("person") }, label = { Text("Человек") })
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected == "image", { onSelected("image") }, label = { Text("Фото / EXIF") })
                    }
                    if (selected == "image") OutlinedButton(onClick = onPickImage, enabled = !loading, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Image, null); Spacer(Modifier.width(8.dp)); Text("Выбрать изображение") }
                    Button(onClick = onRun, enabled = !loading && selected != "image", modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Accent)) {
                        if (loading) CircularProgressIndicator(Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
                        else Icon(Icons.Default.Search, null)
                        Spacer(Modifier.width(8.dp))
                        Text(if (loading) "Анализирую…" else "Запустить анализ")
                    }
                    Text(status, color = Muted, fontSize = 12.sp)
                }
            }
        }
        if (result != null) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("РЕЗУЛЬТАТ АНАЛИЗА", color = Accent, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                        Text(result.subject, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Text(result.summary, color = Muted, fontSize = 12.sp)
                        HorizontalDivider(color = Color(0xFF343A42))
                        result.findings.forEach { finding ->
                            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(finding.title, Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                                    Text(finding.value, color = when(finding.level) { "good" -> Color(0xFF75C99A); "warn" -> Color(0xFFE9B76B); else -> Silver }, fontSize = 11.sp)
                                }
                                Text(finding.detail, color = Muted, fontSize = 11.sp)
                            }
                            HorizontalDivider(color = Color(0xFF292E34))
                        }
                    }
                }
            }
            item {
                Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF252126)), shape = RoundedCornerShape(16.dp)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AutoAwesome, null, tint = Accent)
                            Spacer(Modifier.width(8.dp))
                            Text("Объяснение результатов", fontWeight = FontWeight.Bold)
                            Spacer(Modifier.weight(1f))
                            Text("LOCAL", color = Muted, fontSize = 10.sp)
                        }
                        Text(result.explanation, color = Silver, fontSize = 13.sp)
                        OutlinedButton(onClick = { onShare(result) }, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Share, null); Spacer(Modifier.width(8.dp)); Text("Экспортировать отчёт") }
                        Text("Это встроенный локальный аналитический помощник на правилах, не генеративная нейросеть. Он работает без отправки ваших данных в ИИ-сервис.", color = Muted, fontSize = 10.sp)
                    }
                }
            }
        }
        item { Text("Инструменты", fontSize = 18.sp, fontWeight = FontWeight.Bold) }
        items(modules) { module -> ModuleCard(module) }
        item { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
fun ModulesScreen(padding: PaddingValues, modules: List<OsintModule>) {
    LazyColumn(Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text("Модули", fontSize = 25.sp, fontWeight = FontWeight.Bold); Text("Реальный статус функций", color = Muted) }
        items(modules) { ModuleCard(it) }
        item { Text("Username, Email, Domain, IP, URL и локальный EXIF-анализ доступны. Используйте только законные публичные источники.", color = Muted, fontSize = 12.sp) }
    }
}

@Composable
fun ModuleCard(module: OsintModule) {
    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(14.dp)) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(42.dp).background(Color(0xFF302226), RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                Icon(when(module.id) {
                    "username" -> Icons.Default.AlternateEmail
                    "person" -> Icons.Default.Person
                    "email" -> Icons.Default.MarkEmailRead
                    "domain" -> Icons.Default.Language
                    "image" -> Icons.Default.Image
                    "ip" -> Icons.Default.Router
                    "url" -> Icons.Default.Link
                    else -> Icons.Default.Description
                }, null, tint = Accent)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(module.title, fontWeight = FontWeight.Bold)
                Text(module.description, color = Muted, fontSize = 11.sp)
            }
            Text(module.state, color = if (module.state == "Работает") Color(0xFF75C99A) else Accent, fontSize = 10.sp)
        }
    }
}

@Composable
fun HistoryScreen(padding: PaddingValues, history: List<String>) {
    Column(Modifier.fillMaxSize().padding(padding).padding(18.dp)) {
        Text("История", fontSize = 25.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        if (history.isEmpty()) Text("Пока нет выполненных исследований.", color = Muted)
        else LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(history) { entry -> Card(colors = CardDefaults.cardColors(containerColor = Panel)) { Text(entry, Modifier.padding(14.dp), color = Silver, fontSize = 13.sp) } }
        }
    }
}
