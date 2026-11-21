package dev.nercone.replayintegrity.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Protection
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Engine
import dev.nercone.replayintegrity.engine.KeyRemoval
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.net.KeyboxFormat
import dev.nercone.replayintegrity.net.KeyboxSource
import dev.nercone.replayintegrity.ui.Notices.notices

/**
 * The settings: a list of pages, each of one concern, so that no page is a wall of choices.
 * The frame shows a page in place of the list, with a way back (`ReplayApp`).
 */
object SettingsScreen {
    /** Where the source of the application is published. */
    const val SOURCE = "https://github.com/nercone-labs/replay-integrity"

    /** A page of the settings. */
    enum class Page(val title: Int) {
        PROTECTION(R.string.settings_protection),
        REFRESH(R.string.settings_refresh),
        SOURCES(R.string.settings_sources),
        APPLYING(R.string.settings_applying),
        NOTIFICATIONS(R.string.settings_notifications),
        PRIVILEGE(R.string.settings_privilege),
        ABOUT(R.string.settings_about),
    }

    @Composable
    fun Content(data: ScreenData, model: AppViewModel, page: Page?, onOpen: (Page) -> Unit) {
        val state = data.state
        val settings = data.settings
        Widgets.Screen {
            notices(data, model)
            when (page) {
                null -> item(key = "pages") { Pages(state, settings, onOpen) }
                Page.PRIVILEGE -> item(key = "privilege") {
                    Privileges.Choices(state.privilege, settings.privilege, enabled = state.operation == null, onSelect = model::setPrivilegeChoice)
                }
                Page.PROTECTION -> item(key = "protection") { Protection(settings, model) }
                Page.REFRESH -> item(key = "refresh") { Refresh(settings, model) }
                Page.SOURCES -> item(key = "sources") { Sources(settings, model) }
                Page.APPLYING -> item(key = "applying") { Applying(state, settings, model) }
                Page.NOTIFICATIONS -> item(key = "notifications") { Notifications(settings, model) }
                Page.ABOUT -> item(key = "about") { About(state) }
            }
        }
    }

    /** The list of pages, each with a summary of what it is set to. */
    @Composable
    fun Pages(state: UiState, settings: Settings.Values, onOpen: (Page) -> Unit) {
        val protection = Protection.of(settings)
        val pages = listOf(
            Triple(Page.PROTECTION, Icons.Default.Shield, protection?.let { Labels.protection(it) } ?: stringResource(R.string.protection_custom_short)),
            Triple(Page.REFRESH, Icons.Default.Sync, listOf(
                if (settings.refreshHours == 0) stringResource(R.string.refresh_off) else stringResource(R.string.refresh_every, settings.refreshHours),
                Labels.keyboxReplacement(settings.keyboxReplacement),
            ).joinToString(" · ")),
            Triple(Page.SOURCES, Icons.Default.CloudDownload, pluralStringResource(R.plurals.keybox_sources, settings.keyboxSources.size, settings.keyboxSources.size)),
            Triple(Page.APPLYING, Icons.Default.PowerSettingsNew, listOf(
                stringResource(if (settings.restartOnChange) R.string.settings_applying_at_once else R.string.settings_applying_at_reboot),
                stringResource(if (settings.bootHook) R.string.settings_applying_boot_hook else R.string.settings_applying_no_boot_hook),
            ).joinToString(" · ")),
            Triple(Page.NOTIFICATIONS, Icons.Default.Notifications, stringResource(if (settings.notifyFailures) R.string.on else R.string.off)),
            Triple(Page.PRIVILEGE, Icons.Default.Security, Privileges.summary(settings.privilege, state.privilege)),
            Triple(Page.ABOUT, Icons.Default.Info, stringResource(R.string.settings_about_short)),
        )
        Widgets.Group {
            pages.forEachIndexed { index, (page, icon, summary) ->
                Widgets.Item(index, pages.size, stringResource(page.title), summary, icon, onClick = { onOpen(page) })
            }
        }
    }

    @Composable
    fun Protection(settings: Settings.Values, model: AppViewModel) {
        val protection = Protection.of(settings)
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(null, stringResource(if (protection == null) R.string.protection_custom else R.string.protection_help)) {
                Protection.entries.forEachIndexed { index, choice ->
                    Widgets.RadioItem(
                        index, Protection.entries.size,
                        headline = Labels.protection(choice) + if (choice == Protection.DEFAULT) stringResource(R.string.protection_default_suffix) else "",
                        supporting = Labels.protectionHelp(choice),
                        selected = protection == choice,
                    ) { model.setProtection(choice) }
                }
            }
            Widgets.Section(stringResource(R.string.settings_keys), stringResource(R.string.settings_keys_help)) {
                KeyRemovalItem(0, 4, stringResource(R.string.settings_keys_integrity), stringResource(R.string.settings_keys_integrity_help), settings.keyRemoval.integrity) { removal ->
                    model.configure { it.copy(keyRemoval = it.keyRemoval.copy(integrity = removal)) }
                }
                KeyRemovalItem(1, 4, stringResource(R.string.settings_keys_play), stringResource(R.string.settings_keys_play_help), settings.keyRemoval.play) { removal ->
                    model.configure { it.copy(keyRemoval = it.keyRemoval.copy(play = removal)) }
                }
                KeyRemovalItem(2, 4, stringResource(R.string.settings_keys_applications), stringResource(R.string.settings_keys_applications_help), settings.keyRemoval.applications) { removal ->
                    model.configure { it.copy(keyRemoval = it.keyRemoval.copy(applications = removal)) }
                }
                Widgets.SwitchItem(3, 4, stringResource(R.string.settings_keys_patch), stringResource(R.string.settings_keys_patch_help), settings.keyRemoval.integrityPatch) { enabled ->
                    model.configure { it.copy(keyRemoval = it.keyRemoval.copy(integrityPatch = enabled)) }
                }
            }
        }
    }

    /** The removal of one kind of outdated key (`KeyRemovalSettings`), as a choice of `KeyRemoval`. */
    @Composable
    fun KeyRemovalItem(index: Int, count: Int, title: String, help: String, removal: KeyRemoval, onSelect: (KeyRemoval) -> Unit) {
        Widgets.ChoiceItem(
            index, count,
            headline = title,
            options = KeyRemoval.entries,
            selected = removal,
            describe = { Labels.keyRemoval(it) },
            onSelect = onSelect,
            description = help,
            help = { Labels.keyRemovalHelp(it) },
        )
    }

    @Composable
    fun Refresh(settings: Settings.Values, model: AppViewModel) {
        val whenNeeded = settings.keyboxReplacement == Settings.KeyboxReplacement.WHEN_NEEDED
        val items = buildList<@Composable (Int, Int) -> Unit> {
            add { index, count ->
                Widgets.SwitchItem(index, count, stringResource(R.string.settings_auto_keybox), stringResource(R.string.settings_auto_keybox_help), settings.autoKeybox) { enabled ->
                    model.configure { it.copy(autoKeybox = enabled) }
                }
            }
            add { index, count ->
                Widgets.ChoiceItem(
                    index, count,
                    headline = stringResource(R.string.settings_keybox_replacement),
                    options = Settings.KeyboxReplacement.entries,
                    selected = settings.keyboxReplacement,
                    describe = { Labels.keyboxReplacement(it) },
                    onSelect = { replacement -> model.configure { it.copy(keyboxReplacement = replacement) } },
                    help = { Labels.keyboxReplacementHelp(it) },
                    enabled = settings.autoKeybox,
                )
            }
            if (whenNeeded) add { index, count ->
                Widgets.ChoiceItem(
                    index, count,
                    headline = stringResource(R.string.settings_expiry_margin),
                    options = Settings.EXPIRY_MARGIN_CHOICES,
                    selected = settings.keyboxExpiryMarginHours,
                    describe = { hours -> pluralStringResource(R.plurals.hours, hours, hours) },
                    onSelect = { hours -> model.configure { it.copy(keyboxExpiryMarginHours = hours) } },
                    description = stringResource(R.string.settings_expiry_margin_help),
                    enabled = settings.autoKeybox,
                )
            }
            add { index, count ->
                Widgets.SwitchItem(index, count, stringResource(R.string.settings_auto_fingerprint), stringResource(R.string.settings_auto_fingerprint_help), settings.autoFingerprint) { enabled ->
                    model.configure { it.copy(autoFingerprint = enabled) }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(null) { items.forEachIndexed { index, item -> item(index, items.size) } }
            Widgets.Section(stringResource(R.string.settings_schedule)) {
                Widgets.ChoiceItem(
                    0, 2,
                    headline = stringResource(R.string.settings_interval),
                    options = Settings.REFRESH_CHOICES,
                    selected = settings.refreshHours,
                    describe = { hours -> if (hours == 0) stringResource(R.string.off) else pluralStringResource(R.plurals.every_hours, hours, hours) },
                    onSelect = { hours -> model.configure { it.copy(refreshHours = hours) } },
                    description = stringResource(R.string.settings_interval_help),
                )
                Widgets.SwitchItem(1, 2, stringResource(R.string.settings_unmetered), stringResource(R.string.settings_unmetered_help), settings.refreshUnmetered, enabled = settings.refreshHours != 0) { enabled ->
                    model.configure { it.copy(refreshUnmetered = enabled) }
                }
            }
        }
    }

    @Composable
    fun Sources(settings: Settings.Values, model: AppViewModel) {
        val sources = settings.keyboxSources
        // The source being edited, by index, or the size of the list for a new one.
        var editing by rememberSaveable { mutableStateOf<Int?>(null) }
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(stringResource(R.string.settings_keybox_sources), stringResource(R.string.settings_keybox_sources_help)) {
                val count = sources.size + 1
                sources.forEachIndexed { index, source ->
                    Widgets.Item(
                        index, count,
                        headline = source.url,
                        supporting = listOfNotNull(
                            Labels.keyboxFormat(source.format),
                            stringResource(R.string.keybox_source_lenient).takeIf { source.lenient },
                        ).joinToString(" · "),
                        icon = Icons.Default.Link,
                        onClick = { editing = index },
                    )
                }
                Widgets.Item(count - 1, count, stringResource(R.string.keybox_source_add), null, Icons.Default.Add, onClick = { editing = sources.size })
            }
            Widgets.Section(stringResource(R.string.settings_fingerprint_source), stringResource(R.string.settings_sources_help)) {
                Widgets.TextItem(0, 2, stringResource(R.string.settings_fingerprint_url), settings.fingerprintUrl, Downloader::isAcceptable, { url -> model.configure { it.copy(fingerprintUrl = url) } }, Icons.Default.Link, KeyboardType.Uri)
                Widgets.Item(
                    1, 2,
                    headline = stringResource(R.string.settings_sources_reset),
                    supporting = stringResource(R.string.settings_sources_reset_help),
                    icon = Icons.Default.RestartAlt,
                    enabled = sources != Downloader.DEFAULT_KEYBOX_SOURCES || settings.fingerprintUrl != Downloader.DEFAULT_FINGERPRINT_URL,
                    onClick = model::resetSources,
                )
            }
        }
        editing?.takeIf { it <= sources.size }?.let { index ->
            // Keyed by the position edited, so that the draft of one source never carries over to another.
            key(index) { KeyboxSourceDialog(
                source = sources.getOrNull(index),
                others = sources.filterIndexed { i, _ -> i != index }.map { it.url },
                onSave = { saved ->
                    val list = if (index < sources.size) sources.mapIndexed { i, s -> if (i == index) saved else s } else sources + saved
                    model.configure { it.copy(keyboxSources = list) }
                    editing = null
                },
                onRemove = if (index < sources.size) {
                    {
                        model.configure { it.copy(keyboxSources = sources.filterIndexed { i, _ -> i != index }) }
                        editing = null
                    }
                } else {
                    null
                },
                onDismiss = { editing = null },
            ) }
        }
    }

    /**
     * Edits a keybox source, or a new one when `source` is `null`: its URL (HTTPS, and not one of
     * `others`), its format and whether its keybox is read leniently.
     */
    @Composable
    fun KeyboxSourceDialog(source: KeyboxSource?, others: List<String>, onSave: (KeyboxSource) -> Unit, onRemove: (() -> Unit)?, onDismiss: () -> Unit) {
        var url by rememberSaveable { mutableStateOf(source?.url.orEmpty()) }
        var format by rememberSaveable { mutableStateOf(source?.format ?: KeyboxFormat.AUTO) }
        var lenient by rememberSaveable { mutableStateOf(source?.lenient ?: false) }
        val valid = Downloader.isAcceptable(url) && url !in others
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(if (source == null) R.string.keybox_source_add else R.string.keybox_source_edit)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        url,
                        { url = it.trim() },
                        label = { Text(stringResource(R.string.settings_keybox_url)) },
                        singleLine = true,
                        isError = url.isNotEmpty() && !valid,
                        supportingText = if (url in others) {
                            { Text(stringResource(R.string.keybox_source_duplicate)) }
                        } else {
                            null
                        },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(stringResource(R.string.settings_keybox_format), style = MaterialTheme.typography.labelLarge)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        KeyboxFormat.entries.forEach { option ->
                            FilterChip(selected = format == option, onClick = { format = option }, label = { Text(Labels.keyboxFormat(option)) })
                        }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(stringResource(R.string.settings_keybox_lenient), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        Switch(lenient, { lenient = it })
                    }
                }
            },
            confirmButton = { TextButton(enabled = valid, onClick = { onSave(KeyboxSource(url, lenient, format)) }) { Text(stringResource(R.string.save)) } },
            dismissButton = {
                Row {
                    onRemove?.let { TextButton(onClick = it) { Text(stringResource(R.string.remove)) } }
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                }
            },
        )
    }

    @Composable
    fun Applying(state: UiState, settings: Settings.Values, model: AppViewModel) {
        val idle = state.idle
        val hook = state.status?.bootHook
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(null) {
                Widgets.SwitchItem(0, 3, stringResource(R.string.settings_restart_on_change), stringResource(R.string.settings_restart_on_change_help), settings.restartOnChange) { enabled ->
                    model.configure { it.copy(restartOnChange = enabled) }
                }
                Widgets.SwitchItem(1, 3, stringResource(R.string.settings_end_background), stringResource(R.string.settings_end_background_help), settings.endBackgroundApplications) { enabled ->
                    model.configure { it.copy(endBackgroundApplications = enabled) }
                }
                Widgets.Item(2, 3, stringResource(R.string.settings_restart_now), stringResource(R.string.settings_restart_now_help), Icons.Default.RestartAlt, enabled = idle, onClick = model::restart)
            }
            Widgets.Section(stringResource(R.string.settings_boot)) {
                Widgets.SwitchItem(
                    0, 3,
                    headline = stringResource(R.string.settings_boot_hook),
                    supporting = when {
                        hook == null -> stringResource(R.string.settings_boot_hook_help)
                        hook.managers.isEmpty() -> stringResource(R.string.boot_hook_unsupported)
                        hook.installed -> stringResource(R.string.boot_hook_installed, Labels.rootManagers(hook.managers))
                        else -> stringResource(R.string.settings_boot_hook_pending, Labels.rootManagers(hook.managers))
                    },
                    checked = settings.bootHook,
                    enabled = idle,
                    onChange = model::setBootHook,
                )
                Widgets.SwitchItem(
                    1, 3,
                    headline = stringResource(R.string.settings_watch_packages),
                    supporting = stringResource(if (hook?.watcher != null) R.string.settings_watch_packages_running else R.string.settings_watch_packages_help),
                    checked = settings.watchPackages,
                    enabled = idle && settings.bootHook,
                    onChange = model::setWatchPackages,
                )
                Widgets.SwitchItem(2, 3, stringResource(R.string.settings_repair_after_boot), stringResource(R.string.settings_repair_after_boot_help), settings.repairAfterBoot) { enabled ->
                    model.configure { it.copy(repairAfterBoot = enabled) }
                }
            }
        }
    }

    @Composable
    fun Notifications(settings: Settings.Values, model: AppViewModel) {
        val context = LocalContext.current
        var granted by remember { mutableStateOf(context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) }
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
        Widgets.Section(null) {
            Widgets.SwitchItem(
                0, 1,
                stringResource(R.string.settings_notify_failures),
                stringResource(if (granted || !settings.notifyFailures) R.string.settings_notify_failures_help else R.string.settings_notify_denied),
                settings.notifyFailures,
            ) { enabled ->
                model.configure { it.copy(notifyFailures = enabled) }
                if (enabled && !granted) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    @Composable
    fun About(state: UiState) {
        val context = LocalContext.current
        val version = remember { runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull().orEmpty() }
        val uri = LocalUriHandler.current
        var credits by rememberSaveable { mutableStateOf(false) }
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Identity(stringResource(R.string.settings_version, version, state.status?.engineVersion ?: "?"))
            Widgets.Section(null, stringResource(R.string.settings_uninstall)) {
                Widgets.Item(0, 4, stringResource(R.string.settings_store_title), stringResource(R.string.settings_store, Engine.STORE), Icons.Default.Folder)
                Widgets.Item(1, 4, stringResource(R.string.settings_capabilities), state.status?.let { status ->
                    if (status.missingCapabilities.isEmpty()) stringResource(R.string.settings_capabilities_ok) else status.missingCapabilities.joinToString(", ")
                } ?: stringResource(R.string.unknown), Icons.Default.AdminPanelSettings)
                Widgets.Item(2, 4, stringResource(R.string.settings_credits), stringResource(R.string.settings_credits_short), Icons.Default.People, onClick = { credits = true })
                Widgets.Item(3, 4, stringResource(R.string.settings_source_title), SOURCE, Icons.Default.Code, onClick = { Widgets.open(uri, SOURCE) })
            }
        }
        if (credits) {
            AlertDialog(
                onDismissRequest = { credits = false },
                title = { Text(stringResource(R.string.settings_credits)) },
                text = { Text(stringResource(R.string.settings_credits_text)) },
                confirmButton = { TextButton(onClick = { credits = false }) { Text(stringResource(R.string.dismiss)) } },
            )
        }
    }
}
