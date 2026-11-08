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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Bg = Color(0xFF101215)
private val Panel = Color(0xFF1A1E23)
private val Accent = Color(0xFFE04B50)
private val Silver = Color(0xFFD5D9DE)
private val Muted = Color(0xFF929AA4)

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
            OsintModule("username", "Username OSINT", "Проверка публичных профилей на популярных площадках", "Идентификаторы", "Работает"),
            OsintModule("email", "Email OSINT", "Синтаксис адреса и DNS/MX домена почты", "Идентификаторы", "Работает"),
            OsintModule("domain", "Domain OSINT", "DNS A/AAAA/MX/NS и регистрационные RDAP-данные", "Инфраструктура", "Работает"),
            OsintModule("image", "Image & Metadata", "EXIF выбранных фотографий — следующий этап", "Медиа", "В разработке"),
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
                            appendLine("OpenScope OSINT — ${analysis.module}")
                            appendLine("Объект: ${analysis.subject}")
                            appendLine(analysis.summary)
                            analysis.findings.forEach { appendLine("\\n${it.title}: ${it.value}\\n${it.detail}") }
                            appendLine("\\nОбъяснение: ${analysis.explanation}")
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
                                    val analysis = AnalysisEngine.run(selected, input)
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
    LazyColumn(Modifier.fillMaxSize().padding(padding).padding(horizontal = 18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
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
                    OutlinedTextField(value = query, onValueChange = onQuery, modifier = Modifier.fillMaxWidth(), label = { Text("Никнейм, email или домен") }, singleLine = true)
                    Text("Тип исследования", color = Muted, fontSize = 12.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected == "username", { onSelected("username") }, label = { Text("Никнейм") })
                        FilterChip(selected == "email", { onSelected("email") }, label = { Text("Email") })
                        FilterChip(selected == "domain", { onSelected("domain") }, label = { Text("Домен") })\n                        FilterChip(selected == "ip", { onSelected("ip") }, label = { Text("IP") })\n                        FilterChip(selected == "url", { onSelected("url") }, label = { Text("URL") })
                    }
                    if (selected == "image") OutlinedButton(onClick = onPickImage, enabled = !loading, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Image, null); Spacer(Modifier.width(8.dp)); Text("Выбрать изображение") }\n                    Button(onClick = onRun, enabled = !loading && selected != "image", modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Accent)) {
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
                        Text(result.explanation, color = Silver, fontSize = 13.sp)\n                        OutlinedButton(onClick = { onShare(result) }, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Share, null); Spacer(Modifier.width(8.dp)); Text("Экспортировать отчёт") }
                        Text("Это встроенный локальный аналитический помощник на правилах, не генеративная нейросеть. Он работает без отправки ваших данных в ИИ-сервис.", color = Muted, fontSize = 10.sp)
                    }
                }
            }
        }
        item { Text("Инструменты", fontSize = 18.sp, fontWeight = FontWeight.Bold) }
        items(modules.take(4)) { module -> ModuleCard(module) }
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
                    "email" -> Icons.Default.MarkEmailRead
                    "domain" -> Icons.Default.Language
                    "image" -> Icons.Default.Image
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
