package dev.nercone.replayintegrity.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeChoice

/** Settings of the application: the privilege, the refresh, the boot, the notifications. */
object SettingsScreen {
    const val STORE = "/data/adb/replay-integrity"

    @Composable
    fun Content(state: UiState, settings: Settings.Values, model: AppViewModel) {
        val privileged = state.privilege?.privilege != null && state.operation == null
        val context = LocalContext.current
        var granted by remember { mutableStateOf(context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) }
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Widgets.Header(stringResource(R.string.settings_privilege))
            Widgets.Group {
                PrivilegeChoice.entries.forEachIndexed { index, choice ->
                    Widgets.RadioItem(
                        index, PrivilegeChoice.entries.size,
                        headline = stringResource(
                            when (choice) {
                                PrivilegeChoice.AUTOMATIC -> R.string.settings_privilege_automatic
                                PrivilegeChoice.SHIZUKU -> R.string.settings_privilege_shizuku
                                PrivilegeChoice.ROOT -> R.string.settings_privilege_root
                            },
                        ),
                        supporting = state.privilege?.statuses?.let { statuses ->
                            when (choice) {
                                PrivilegeChoice.AUTOMATIC -> state.privilege.privilege?.let { stringResource(R.string.privilege_runs_as_root, Labels.privilege(it.kind)) }
                                else -> statuses.firstOrNull { (kind, _) -> (kind == Privilege.Kind.ROOT) == (choice == PrivilegeChoice.ROOT) }
                                    ?.let { (_, status) -> Labels.describe(status) }
                            }
                        },
                        selected = settings.privilege == choice,
                    ) { model.setPrivilegeChoice(choice) }
                }
            }
            Text(stringResource(R.string.settings_privilege_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

            Widgets.Header(stringResource(R.string.settings_refresh))
            Widgets.Group {
                Widgets.SwitchItem(0, 4, stringResource(R.string.settings_auto_keybox), stringResource(R.string.settings_auto_keybox_help), settings.autoKeybox) { enabled ->
                    model.configure { it.copy(autoKeybox = enabled) }
                }
                Widgets.SwitchItem(1, 4, stringResource(R.string.settings_auto_fingerprint), stringResource(R.string.settings_auto_fingerprint_help), settings.autoFingerprint) { enabled ->
                    model.configure { it.copy(autoFingerprint = enabled) }
                }
                Widgets.Panel(2, 4) {
                    Text(stringResource(R.string.settings_interval), style = MaterialTheme.typography.bodyLarge)
                    Widgets.Segments(
                        Settings.REFRESH_CHOICES,
                        settings.refreshHours,
                        { hours -> if (hours == 0) stringResource(R.string.off) else stringResource(R.string.hours_short, hours) },
                        { hours -> model.configure { it.copy(refreshHours = hours) } },
                    )
                    Text(stringResource(R.string.settings_interval_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary)
                }
                Widgets.SwitchItem(3, 4, stringResource(R.string.settings_unmetered), stringResource(R.string.settings_unmetered_help), settings.refreshUnmetered, enabled = settings.refreshHours != 0) { enabled ->
                    model.configure { it.copy(refreshUnmetered = enabled) }
                }
            }

            Widgets.Header(stringResource(R.string.settings_sources))
            Widgets.Group {
                Widgets.Panel(0, 4) {
                    Widgets.TextSetting(settings.keyboxUrl, stringResource(R.string.settings_keybox_url), Downloader::isAcceptable, { url -> model.configure { it.copy(keyboxUrl = url) } })
                }
                Widgets.Panel(1, 4) {
                    Text(stringResource(R.string.settings_extra_keybox_urls), style = MaterialTheme.typography.labelLarge)
                    Widgets.StringList(
                        items = settings.extraKeyboxUrls,
                        label = stringResource(R.string.settings_keybox_url),
                        validate = { Downloader.isAcceptable(it) && it != settings.keyboxUrl },
                        onChange = { list -> model.configure { it.copy(extraKeyboxUrls = list) } },
                    )
                    Text(stringResource(R.string.settings_extra_keybox_urls_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary)
                }
                Widgets.Panel(2, 4) {
                    Widgets.TextSetting(settings.fingerprintUrl, stringResource(R.string.settings_fingerprint_url), Downloader::isAcceptable, { url -> model.configure { it.copy(fingerprintUrl = url) } })
                }
                Widgets.Item(
                    3, 4,
                    headline = stringResource(R.string.settings_sources_reset),
                    supporting = stringResource(R.string.settings_sources_reset_help),
                    enabled = settings.keyboxUrl != Downloader.DEFAULT_KEYBOX_URL || settings.extraKeyboxUrls.isNotEmpty() || settings.fingerprintUrl != Downloader.DEFAULT_FINGERPRINT_URL,
                    onClick = model::resetSources,
                )
            }
            Text(stringResource(R.string.settings_sources_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

            Widgets.Header(stringResource(R.string.settings_behavior))
            Widgets.Group {
                Widgets.SwitchItem(0, 2, stringResource(R.string.settings_restart_on_change), stringResource(R.string.settings_restart_on_change_help), settings.restartOnChange) { enabled ->
                    model.configure { it.copy(restartOnChange = enabled) }
                }
                Widgets.Item(1, 2, stringResource(R.string.settings_restart_now), stringResource(R.string.settings_restart_now_help), enabled = privileged, onClick = model::restart)
            }

            Widgets.Header(stringResource(R.string.settings_boot))
            val hook = state.status?.bootHook
            Widgets.Group {
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
                    enabled = privileged,
                    onChange = model::setBootHook,
                )
                Widgets.SwitchItem(
                    1, 3,
                    headline = stringResource(R.string.settings_watch_packages),
                    supporting = when {
                        hook?.watcher != null -> stringResource(R.string.settings_watch_packages_running)
                        else -> stringResource(R.string.settings_watch_packages_help)
                    },
                    checked = settings.watchPackages,
                    enabled = privileged && settings.bootHook,
                    onChange = model::setWatchPackages,
                )
                Widgets.SwitchItem(2, 3, stringResource(R.string.settings_repair_after_boot), stringResource(R.string.settings_repair_after_boot_help), settings.repairAfterBoot) { enabled ->
                    model.configure { it.copy(repairAfterBoot = enabled) }
                }
            }

            Widgets.Header(stringResource(R.string.settings_notifications))
            Widgets.Group {
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

            Widgets.Header(stringResource(R.string.settings_about))
            val version = remember { context.packageManager.getPackageInfo(context.packageName, 0).versionName.orEmpty() }
            var credits by remember { mutableStateOf(false) }
            Widgets.Group {
                Widgets.Item(0, 4, stringResource(R.string.app_name), stringResource(R.string.settings_version, version, state.status?.engineVersion ?: "?"))
                Widgets.Item(1, 4, stringResource(R.string.settings_store_title), stringResource(R.string.settings_store, STORE))
                Widgets.Item(2, 4, stringResource(R.string.settings_capabilities), state.status?.let { status ->
                    if (status.missingCapabilities.isEmpty()) stringResource(R.string.settings_capabilities_ok) else status.missingCapabilities.joinToString(", ")
                } ?: stringResource(R.string.unknown))
                Widgets.Item(3, 4, stringResource(R.string.settings_credits), stringResource(R.string.settings_credits_short), onClick = { credits = true })
            }
            Text(stringResource(R.string.settings_uninstall), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(16.dp))
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
}
