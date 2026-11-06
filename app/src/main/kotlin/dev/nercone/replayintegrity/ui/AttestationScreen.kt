package dev.nercone.replayintegrity.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Unarchive
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.Replay
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.FingerprintReport
import dev.nercone.replayintegrity.engine.InstalledFile
import dev.nercone.replayintegrity.engine.KeyVerdict
import dev.nercone.replayintegrity.engine.KeyboxVerdict
import dev.nercone.replayintegrity.engine.SpoofFlag
import dev.nercone.replayintegrity.engine.StatusReport

/** The pieces of attestation: the keybox, the fingerprint, the spoof flags and the modules. */
object AttestationScreen {
    /** The MIME types offered when importing a keybox, a fingerprint or a module. */
    val KEYBOX_TYPES = arrayOf("text/xml", "application/xml", "text/plain", "application/octet-stream")
    /** A fingerprint is a `custom.pif.prop` or a `custom.pif.json`. */
    val FINGERPRINT_TYPES = arrayOf("text/plain", "application/json", "application/octet-stream", "*/*")
    val MODULE_TYPES = arrayOf("application/zip", "application/x-zip-compressed", "application/octet-stream")

    @Composable
    fun Content(state: UiState, settings: Settings.Values, model: AppViewModel) {
        val idle = state.operation == null && state.privilege?.privilege != null
        val keyboxPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(model::inspectKeybox) }
        val fingerprintPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(model::inspectFingerprint) }
        var module by rememberSaveable { mutableStateOf<Component?>(null) }
        val modulePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            val component = module
            if (uri != null && component != null) model.installModule(component, uri)
        }
        val status = state.status
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (status == null) {
                Widgets.Notice(Widgets.Tone.INFORMATION, stringResource(R.string.no_status_title), stringResource(R.string.no_status_text))
            }
            HomeScreen.Pending(state, settings, model)
            Widgets.Header(stringResource(R.string.section_keybox))
            Keybox(status?.keybox, status?.keyboxInstalled)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = { keyboxPicker.launch(KEYBOX_TYPES) }, enabled = idle) {
                    Icon(Icons.Default.FileOpen, null, Modifier.padding(end = 8.dp))
                    Text(stringResource(R.string.import_keybox))
                }
            }
            Text(
                stringResource(if (settings.autoKeybox) R.string.keybox_auto_on else R.string.keybox_auto_off),
                style = MaterialTheme.typography.bodySmall,
                color = Widgets.secondary,
                modifier = Modifier.padding(horizontal = 16.dp),
            )

            Widgets.Header(stringResource(R.string.section_fingerprint))
            Fingerprint(status?.fingerprint, status?.fingerprintInstalled)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = { fingerprintPicker.launch(FINGERPRINT_TYPES) }, enabled = idle) {
                    Icon(Icons.Default.FileOpen, null, Modifier.padding(end = 8.dp))
                    Text(stringResource(R.string.import_fingerprint))
                }
            }
            Text(
                stringResource(if (settings.autoFingerprint) R.string.fingerprint_auto_on else R.string.fingerprint_auto_off),
                style = MaterialTheme.typography.bodySmall,
                color = Widgets.secondary,
                modifier = Modifier.padding(horizontal = 16.dp),
            )

            Widgets.Header(stringResource(R.string.section_spoof))
            Spoof(status, settings, model)
            Text(stringResource(R.string.spoof_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

            Widgets.Header(stringResource(R.string.section_modules))
            Modules(status, idle, onDisableConflicts = model::disableConflicts) { component ->
                module = component
                modulePicker.launch(MODULE_TYPES)
            }
            Text(stringResource(R.string.modules_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))
        }
        state.candidate?.let { Candidate(it, onInstall = { model.install(it) }, onDismiss = model::dismissCandidate) }
    }

    @Composable
    fun Keybox(keybox: KeyboxVerdict?, installed: InstalledFile?) {
        if (keybox == null) {
            Widgets.Group { Widgets.Item(0, 1, stringResource(R.string.keybox_none), stringResource(R.string.keybox_none_help), Icons.Default.Key) }
            return
        }
        val count = keybox.keys.size + 1
        Widgets.Group {
            Widgets.Panel(0, count) {
                Widgets.Field(stringResource(R.string.keybox_summary), stringResource(R.string.keybox_usable, keybox.usableKeys, keybox.keys.size))
                Widgets.Field(
                    stringResource(R.string.keybox_strong),
                    stringResource(
                        if (keybox.strongCapable) R.string.yes else R.string.keybox_strong_needs,
                    ),
                )
                Widgets.Field(stringResource(R.string.keybox_revocation), stringResource(if (keybox.revocationChecked) R.string.keybox_revocation_checked else R.string.keybox_revocation_unchecked))
                keybox.expires?.let { Widgets.Field(stringResource(R.string.keybox_expires), Labels.date(it)) }
                installed?.let { InstalledFields(it) }
            }
            keybox.keys.forEachIndexed { index, key -> Key(index + 1, count, key) }
        }
    }

    @Composable
    fun Key(index: Int, count: Int, key: KeyVerdict) {
        Widgets.Panel(index, count) {
            Text(
                stringResource(if (key.usable) R.string.key_usable else R.string.key_unusable, key.algorithm.uppercase()),
                style = MaterialTheme.typography.titleSmall,
                color = if (key.usable) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
            if (key.serial.isNotEmpty()) Widgets.Field(stringResource(R.string.key_serial), key.serial, monospace = true)
            key.root?.let { Widgets.Field(stringResource(R.string.key_root), it, monospace = true) }
            key.expires?.let { Widgets.Field(stringResource(R.string.key_expires), Labels.date(it)) }
            if (key.problems.isNotEmpty()) Widgets.Field(stringResource(R.string.key_problems), key.problems.map { Labels.problem(it) }.joinToString("\n"))
        }
    }

    @Composable
    fun InstalledFields(installed: InstalledFile) {
        Widgets.Field(stringResource(R.string.installed_source), installed.source ?: stringResource(R.string.unknown))
        Widgets.Field(stringResource(R.string.installed_at), Labels.dateTime(installed.installedAt))
        Widgets.Field(stringResource(R.string.installed_sha256), Labels.shortHash(installed.sha256), monospace = true)
    }

    @Composable
    fun Fingerprint(fingerprint: FingerprintReport?, installed: InstalledFile?) {
        Widgets.Group {
            if (fingerprint == null) {
                Widgets.Item(0, 1, stringResource(R.string.fingerprint_none), stringResource(R.string.fingerprint_none_help), Icons.Default.Fingerprint)
                return@Group
            }
            Widgets.Panel(0, 1) {
                FingerprintFields(fingerprint)
                installed?.let { InstalledFields(it) }
            }
        }
    }

    @Composable
    fun FingerprintFields(fingerprint: FingerprintReport) {
        fingerprint.fingerprint?.let { Widgets.Field(stringResource(R.string.fingerprint_build), it, monospace = true) }
        Widgets.Field(stringResource(R.string.fingerprint_device), listOfNotNull(fingerprint.manufacturer, fingerprint.model, fingerprint.device?.let { "($it)" }).joinToString(" "))
        fingerprint.securityPatch?.let { Widgets.Field(stringResource(R.string.fingerprint_security_patch), it) }
        fingerprint.expires?.let { Widgets.Field(stringResource(R.string.fingerprint_accepted_until), Labels.date(it)) }
        if (fingerprint.problems.isNotEmpty()) Widgets.Field(stringResource(R.string.key_problems), fingerprint.problems.map { Labels.problem(it) }.joinToString("\n"))
    }

    /** The spoof flags: what the settings choose, what `apply` writes, and what the module reads now. */
    @Composable
    fun Spoof(status: StatusReport?, settings: Settings.Values, model: AppViewModel) {
        val applied = status?.appliedSpoof().orEmpty()
        val live = status?.integrity?.spoofFlags().orEmpty()
        Widgets.Group {
            SpoofFlag.ALL.forEachIndexed { index, key ->
                Widgets.Panel(index, SpoofFlag.ALL.size) {
                    Text(Labels.spoofFlag(key), style = MaterialTheme.typography.bodyLarge)
                    Text(
                        listOfNotNull(
                            key,
                            applied[key]?.let { stringResource(R.string.spoof_value_applied, onOff(it)) },
                            live[key]?.let { stringResource(R.string.spoof_value_live, onOff(it)) },
                        ).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (live[key] != null && applied[key] != null && live[key] != applied[key]) MaterialTheme.colorScheme.error else Widgets.secondary,
                    )
                    val choice: Boolean? = settings.spoofOverrides[key]
                    Widgets.Segments(
                        options = listOf<Boolean?>(null, true, false),
                        selected = choice,
                        describe = { option ->
                            when (option) {
                                null -> stringResource(R.string.spoof_recommended)
                                true -> stringResource(R.string.on)
                                false -> stringResource(R.string.off)
                            }
                        },
                        onSelect = { model.setSpoof(key, it) },
                    )
                }
            }
        }
        status?.securityPatch?.let { patch ->
            Widgets.Group { Widgets.Panel(0, 1) { Widgets.Field(stringResource(R.string.security_patch_file), patch, monospace = true) } }
        }
    }

    @Composable
    fun onOff(value: Boolean): String = stringResource(if (value) R.string.on else R.string.off)

    @Composable
    fun Modules(status: StatusReport?, idle: Boolean, onDisableConflicts: () -> Unit, onInstall: (Component) -> Unit) {
        val context = LocalContext.current
        Widgets.Group {
            Component.entries.forEachIndexed { index, component ->
                val module = status?.component(component)?.module
                Widgets.Panel(index, Component.entries.size) {
                    Text(Labels.component(component), style = MaterialTheme.typography.bodyLarge)
                    if (module == null) {
                        Text(stringResource(R.string.component_missing, Labels.moduleName(component)), style = MaterialTheme.typography.bodyMedium, color = Widgets.secondary)
                    } else {
                        Widgets.Field(stringResource(R.string.module_name), "${module.name ?: module.id} (${module.id})")
                        Widgets.Field(stringResource(R.string.module_version), listOfNotNull(module.version, module.versionCode?.toString()).joinToString(" / "))
                        module.author?.let { Widgets.Field(stringResource(R.string.module_author), it) }
                        Widgets.Field(
                            stringResource(R.string.module_state),
                            stringResource(
                                when {
                                    module.disabled -> R.string.module_disabled
                                    module.removing -> R.string.module_removing
                                    module.updatePending -> R.string.module_update_pending
                                    else -> R.string.module_active
                                },
                            ),
                        )
                    }
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onInstall(component) }, enabled = idle) {
                            Icon(Icons.Default.Unarchive, null, Modifier.padding(end = 8.dp))
                            Text(stringResource(R.string.module_install))
                        }
                        TextButton(onClick = {
                            try {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Labels.moduleReleases(component))))
                            } catch (_: ActivityNotFoundException) {
                            }
                        }) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, null, Modifier.padding(end = 8.dp))
                            Text(stringResource(R.string.module_releases))
                        }
                    }
                }
            }
        }
        status?.conflicts?.takeIf { it.isNotEmpty() }?.let { conflicts ->
            val text = conflicts.joinToString("\n") { "${it.name ?: it.id} (${it.id})" } + "\n" + stringResource(R.string.conflicts_disable_help)
            Widgets.Notice(Widgets.Tone.ERROR, stringResource(R.string.check_conflicts), text) {
                TextButton(onClick = onDisableConflicts, enabled = idle) { Text(stringResource(R.string.conflicts_disable)) }
            }
        }
    }

    /** Shows what the engine found in a file the user chose, and asks whether to install it. */
    @Composable
    fun Candidate(candidate: Replay.Candidate, onInstall: () -> Unit, onDismiss: () -> Unit) {
        val installable = when (candidate) {
            is Replay.Candidate.Keybox -> candidate.verdict.keys.isNotEmpty() && candidate.verdict.keys.none { key -> key.problems.any { it.kind == "keyMismatch" } }
            is Replay.Candidate.Fingerprint -> candidate.report.ok
        }
        AlertDialog(
            onDismissRequest = onDismiss,
            icon = { Icon(if (candidate is Replay.Candidate.Keybox) Icons.Default.Key else Icons.Default.Extension, null) },
            title = { Text(stringResource(if (candidate is Replay.Candidate.Keybox) R.string.candidate_keybox else R.string.candidate_fingerprint)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Widgets.Field(stringResource(R.string.candidate_file), candidate.name)
                    when (candidate) {
                        is Replay.Candidate.Keybox -> {
                            val verdict = candidate.verdict
                            Widgets.Field(stringResource(R.string.keybox_summary), stringResource(R.string.keybox_usable, verdict.usableKeys, verdict.keys.size))
                            Widgets.Field(stringResource(R.string.keybox_strong), stringResource(if (verdict.strongCapableOnceInstalled) R.string.yes else R.string.keybox_strong_needs))
                            if (verdict.defect != null) Widgets.Field(stringResource(R.string.candidate_malformed), verdict.defect)
                            verdict.keys.filter { !it.usable }.forEach { key ->
                                Widgets.Field(key.algorithm.uppercase(), key.problems.map { Labels.problem(it) }.joinToString("\n"))
                            }
                        }
                        is Replay.Candidate.Fingerprint -> FingerprintFields(candidate.report)
                    }
                    Text(
                        stringResource(if (installable) R.string.candidate_help else R.string.candidate_refused),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (installable) Widgets.secondary else MaterialTheme.colorScheme.error,
                    )
                }
            },
            confirmButton = { TextButton(onClick = onInstall, enabled = installable) { Text(stringResource(R.string.install)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
        )
    }
}
