package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.ComponentState
import dev.nercone.replayintegrity.engine.Flavor
import dev.nercone.replayintegrity.engine.RootManager
import dev.nercone.replayintegrity.engine.StatusReport
import java.text.DateFormat
import java.util.Date

object HomeScreen {
    @Composable
    fun Content(state: UiState, model: AppViewModel) {
        val status = state.status
        val busy = state.operation != null
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Verdict(status)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = model::refreshNow, enabled = !busy, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_refresh))
                }
                OutlinedButton(onClick = model::repair, enabled = !busy && status != null, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.action_repair))
                }
            }
            (state.outcome as? Outcome.Failed)?.let { FailureCard(it.text) }
            (state.outcome as? Outcome.Refreshed)?.takeIf { it.warnings.isNotEmpty() }?.let { WarningsCard(it.warnings) }
            if (status != null) {
                Components(status)
                Keybox(status)
                Fingerprint(status)
                System(status)
            }
            Spacer(Modifier.height(8.dp))
        }
    }

    @Composable
    fun Verdict(status: StatusReport?) {
        val ready = status?.strongReady == true
        val color = when {
            status == null -> MaterialTheme.colorScheme.surfaceVariant
            ready -> MaterialTheme.colorScheme.primaryContainer
            else -> MaterialTheme.colorScheme.errorContainer
        }
        val onColor = when {
            status == null -> MaterialTheme.colorScheme.onSurfaceVariant
            ready -> MaterialTheme.colorScheme.onPrimaryContainer
            else -> MaterialTheme.colorScheme.onErrorContainer
        }
        Card(colors = CardDefaults.cardColors(containerColor = color)) {
            Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val icon = when {
                    status == null -> Icons.Outlined.HelpOutline
                    ready -> Icons.Filled.CheckCircle
                    else -> Icons.Filled.Error
                }
                Icon(icon, null, tint = onColor, modifier = Modifier.size(48.dp))
                Text(
                    stringResource(if (status == null) R.string.verdict_checking else if (ready) R.string.verdict_strong else R.string.verdict_not_ready),
                    style = MaterialTheme.typography.headlineSmall,
                    color = onColor,
                    textAlign = TextAlign.Center,
                )
                if (status != null) {
                    Text(
                        stringResource(if (ready) R.string.verdict_strong_detail else R.string.verdict_not_ready_detail),
                        style = MaterialTheme.typography.bodyMedium,
                        color = onColor,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }

    @Composable
    fun FailureCard(text: String) {
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Text(text, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.bodyMedium)
        }
    }

    @Composable
    fun WarningsCard(warnings: List<String>) {
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)) {
            Column(Modifier.padding(16.dp)) {
                warnings.forEach { Text(it, style = MaterialTheme.typography.bodyMedium, color = Widgets.secondary) }
            }
        }
    }

    @Composable
    fun Components(status: StatusReport) {
        Widgets.Section(stringResource(R.string.section_components)) {
            Component.entries.forEach { component ->
                val componentState = status.components.find { it.component == component }
                ComponentRow(component, componentState)
            }
        }
    }

    @Composable
    fun ComponentRow(component: Component, state: ComponentState?) {
        val title = stringResource(if (component == Component.KEYSTORE) R.string.component_keystore else R.string.component_integrity)
        val module = state?.module
        val (icon, tint, supporting) = when {
            state == null || module == null -> Triple(Icons.Filled.Error, errorColor(), stringResource(R.string.component_missing))
            state.flavor == Flavor.OTHER -> Triple(Icons.Filled.Warning, warningColor(), stringResource(R.string.component_other, module.name ?: module.id))
            module.disabled || module.removing -> Triple(Icons.Filled.Error, errorColor(), stringResource(R.string.component_disabled))
            module.updatePending -> Triple(Icons.Filled.Warning, warningColor(), stringResource(R.string.component_update_pending))
            else -> Triple(Icons.Filled.CheckCircle, okColor(), stringResource(R.string.component_installed, module.version ?: "?"))
        }
        Widgets.StatusRow(icon, tint, title, supporting)
    }

    @Composable
    fun Keybox(status: StatusReport) {
        Widgets.Section(stringResource(R.string.section_keybox)) {
            val keybox = status.keybox
            if (keybox == null) {
                Widgets.StatusRow(Icons.Filled.Error, errorColor(), stringResource(R.string.keybox_none))
            } else {
                val ok = keybox.usableKeys > 0
                Widgets.StatusRow(
                    if (ok) Icons.Filled.CheckCircle else Icons.Filled.Error,
                    if (ok) okColor() else errorColor(),
                    stringResource(R.string.keybox_usable, keybox.usableKeys, keybox.keys.size),
                    keybox.expires()?.let { stringResource(R.string.keybox_expires, formatDate(it)) },
                )
                if (!keybox.revocationChecked) {
                    Widgets.StatusRow(Icons.Filled.Warning, warningColor(), stringResource(R.string.keybox_revocation_unchecked))
                }
                keybox.keys.filter { !it.usable }.forEach { key ->
                    Widgets.StatusRow(Icons.Filled.Warning, warningColor(), stringResource(R.string.keybox_problem, key.algorithm, key.problemKinds().joinToString(", ")))
                }
            }
        }
    }

    @Composable
    fun Fingerprint(status: StatusReport) {
        Widgets.Section(stringResource(R.string.section_fingerprint)) {
            val fingerprint = status.fingerprint
            if (fingerprint == null) {
                Widgets.StatusRow(Icons.Filled.Error, errorColor(), stringResource(R.string.fingerprint_none))
            } else {
                val ok = fingerprint.ok
                Widgets.StatusRow(
                    if (ok) Icons.Filled.CheckCircle else Icons.Filled.Error,
                    if (ok) okColor() else errorColor(),
                    stringResource(R.string.fingerprint_model, fingerprint.model ?: "?", fingerprint.device ?: "?"),
                    fingerprint.securityPatch?.let { stringResource(R.string.fingerprint_patch, it) },
                )
                fingerprint.expires?.let { Widgets.StatusRow(Icons.Filled.CheckCircle, Widgets.secondary, stringResource(R.string.fingerprint_expires, formatDate(it))) }
                if (!ok) {
                    Widgets.StatusRow(Icons.Filled.Warning, warningColor(), stringResource(R.string.fingerprint_problem, fingerprint.problemKinds().joinToString(", ")))
                }
            }
        }
    }

    @Composable
    fun System(status: StatusReport) {
        Widgets.Section(stringResource(R.string.section_system)) {
            val root = status.rootManager
            Widgets.StatusRow(
                if (root != null) Icons.Filled.CheckCircle else Icons.Filled.Error,
                if (root != null) okColor() else errorColor(),
                if (root != null) stringResource(R.string.system_root, rootName(root)) else stringResource(R.string.system_root_none),
            )
            val zygisk = status.zygisk?.available == true
            Widgets.StatusRow(
                if (zygisk) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                if (zygisk) okColor() else warningColor(),
                stringResource(if (zygisk) R.string.system_zygisk_ok else R.string.system_zygisk_missing),
            )
            Widgets.StatusRow(
                if (status.daemonRunning) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                if (status.daemonRunning) okColor() else warningColor(),
                stringResource(if (status.daemonRunning) R.string.system_daemon_running else R.string.system_daemon_stopped),
            )
            if (status.staleKeys > 0) {
                Widgets.StatusRow(Icons.Filled.Warning, warningColor(), stringResource(R.string.system_stale_keys, status.staleKeys))
            }
            status.conflicts.forEach { module ->
                Widgets.StatusRow(Icons.Filled.Warning, warningColor(), stringResource(R.string.system_conflict, module.name ?: module.id))
            }
            Widgets.StatusRow(
                if (status.bootHook) Icons.Filled.CheckCircle else Icons.Outlined.HelpOutline,
                Widgets.secondary,
                stringResource(if (status.bootHook) R.string.system_boot_hook_on else R.string.system_boot_hook_off),
                status.repairedAt?.let { stringResource(R.string.system_last_repair, formatDate(it)) },
            )
        }
    }

    @Composable private fun okColor(): Color = MaterialTheme.colorScheme.primary
    @Composable private fun warningColor(): Color = MaterialTheme.colorScheme.tertiary
    @Composable private fun errorColor(): Color = MaterialTheme.colorScheme.error

    fun rootName(root: RootManager): String = when (root) {
        RootManager.MAGISK -> "Magisk"
        RootManager.KERNEL_SU -> "KernelSU"
        RootManager.APATCH -> "APatch"
    }

    /** A Unix-seconds time as a local date. */
    fun formatDate(seconds: Long): String = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(seconds * 1000))
}
