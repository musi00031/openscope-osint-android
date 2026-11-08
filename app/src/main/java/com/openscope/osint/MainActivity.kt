package com.openscope.osint

import android.os.Bundle
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
    var history by remember { mutableStateOf(listOf<String>()) }
    val modules = remember {
        listOf(
            OsintModule("username", "Username OSINT", "Подготовка поиска публичных профилей", "Идентификаторы", "Локальный модуль"),
            OsintModule("email", "Email OSINT", "Проверка собственных адресов и публичных следов", "Идентификаторы", "Каркас"),
            OsintModule("domain", "Domain OSINT", "Пассивная информация о домене и DNS", "Инфраструктура", "Каркас"),
            OsintModule("image", "Image & Metadata", "Анализ EXIF и свойств локальных файлов", "Медиа", "Каркас"),
            OsintModule("report", "Отчёты", "Локальные заметки и экспорт результатов", "Аналитика", "Готово")
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
                    modules, status, { status = it }, { history = listOf(it) + history }
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
    status: String, onStatus: (String) -> Unit, onHistory: (String) -> Unit
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
                    Text("Работайте только с открытыми источниками и данными, которые разрешено проверять.", color = Muted, fontSize = 12.sp)
                    OutlinedTextField(value = query, onValueChange = onQuery, modifier = Modifier.fillMaxWidth(), label = { Text("Никнейм, email или домен") }, singleLine = true)
                    Text("Тип исследования", color = Muted, fontSize = 12.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(selected == "username", { onSelected("username") }, label = { Text("Никнейм") })
                        FilterChip(selected == "email", { onSelected("email") }, label = { Text("Email") })
                        FilterChip(selected == "domain", { onSelected("domain") }, label = { Text("Домен") })
                    }
                    Button(
                        onClick = {
                            if (query.isBlank()) onStatus("Введите объект исследования")
                            else {
                                val stamp = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date())
                                onStatus("Задание подготовлено: $query")
                                onHistory("$stamp • ${selected.uppercase()} • $query")
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)
                    ) { Icon(Icons.Default.Search, null); Spacer(Modifier.width(8.dp)); Text("Подготовить исследование") }
                    Text(status, color = Muted, fontSize = 12.sp)
                }
            }
        }
        item { Text("Инструменты", fontSize = 18.sp, fontWeight = FontWeight.Bold) }
        items(modules.take(4)) { module -> ModuleCard(module) }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF282024))) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, null, tint = Accent)
                    Spacer(Modifier.width(10.dp))
                    Text("OpenScope — локальный MVP. Внешние движки пока не подключены.", fontSize = 12.sp, color = Silver)
                }
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
fun ModulesScreen(padding: PaddingValues, modules: List<OsintModule>) {
    LazyColumn(Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Text("Модули", fontSize = 25.sp, fontWeight = FontWeight.Bold); Text("Состояние интеграций", color = Muted) }
        items(modules) { ModuleCard(it) }
        item { Text("Следующий этап: подключение локальных адаптеров и проверка совместимости библиотек с Android.", color = Muted, fontSize = 12.sp) }
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
            Text(module.state, color = Accent, fontSize = 10.sp)
        }
    }
}

@Composable
fun HistoryScreen(padding: PaddingValues, history: List<String>) {
    Column(Modifier.fillMaxSize().padding(padding).padding(18.dp)) {
        Text("История", fontSize = 25.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp))
        if (history.isEmpty()) Text("Пока нет подготовленных исследований.", color = Muted)
        else LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(history) { entry -> Card(colors = CardDefaults.cardColors(containerColor = Panel)) { Text(entry, Modifier.padding(14.dp), color = Silver, fontSize = 13.sp) } }
        }
    }
}