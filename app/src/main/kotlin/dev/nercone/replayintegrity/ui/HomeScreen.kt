package dev.nercone.replayintegrity.ui

import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.ComponentState
import dev.nercone.replayintegrity.engine.Flavor
import dev.nercone.replayintegrity.engine.KeyboxVerdict
import dev.nercone.replayintegrity.engine.LogLevel
import dev.nercone.replayintegrity.engine.LogLine
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeStatus

/** The home screen: the verdict, the actions, the outcome, and a checklist of every piece STRONG needs. */
object HomeScreen {
    /** The state of the device, as the hero of the screen tells it. */
    enum class Condition { PREPARING, NO_PRIVILEGE, RESTRICTED, CHECKING, NOT_SET_UP, READY, ATTENTION }

    fun condition(state: UiState, settings: Settings.Values): Condition = when {
        !state.ready -> Condition.PREPARING
        state.privilege != null && state.privilege.privilege == null -> Condition.NO_PRIVILEGE
        state.status == null -> Condition.CHECKING
        state.status.missingCapabilities.isNotEmpty() -> Condition.RESTRICTED
        state.status.strongReady -> Condition.READY
        !settings.applied -> Condition.NOT_SET_UP
        else -> Condition.ATTENTION
    }

    /** How a checklist item stands. */
    enum class Level { OK, WARNING, ERROR, NEUTRAL }

    @Composable
    fun Content(state: UiState, settings: Settings.Values, model: AppViewModel, onNavigate: (ReplayApp.Destination) -> Unit) {
        val condition = condition(state, settings)
        var log by remember { mutableStateOf(false) }
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(Widgets.SPACING),
        ) {
            Hero(condition, state)
            if (condition == Condition.NO_PRIVILEGE) state.privilege?.let { Setup(it, onGrant = model::grantShizuku, onRecheck = model::recheck) }
            Actions(state, condition, settings, model)
            AnimatedVisibility(state.outcome != null && (state.outcome as? Outcome.Failed)?.restricted != true) {
                state.outcome?.let { Outcome(it, onLog = { log = true }, onDismiss = model::dismissOutcome) }
            }
            val status = state.status
            Pending(state, settings, model)
            if (status != null) Checklist(status, settings, onNavigate)
            Details(state, settings, onSettings = { onNavigate(ReplayApp.Destination.SETTINGS) }, onLog = { log = true })
            Device(status?.firstApiLevel)
        }
        if (log) Log(state.log) { log = false }
    }

    /** Tells that the settings changed since they were applied, with the action that applies them. */
    @Composable
    fun Pending(state: UiState, settings: Settings.Values, model: AppViewModel) {
        val status = state.status ?: return
        if (!settings.applied || settings.engine().sameAs(status.settings)) return
        Widgets.Notice(Widgets.Tone.INFORMATION, stringResource(R.string.pending_title), stringResource(R.string.pending_text)) {
            FilledTonalButton(onClick = model::repair, enabled = state.operation == null) { Text(stringResource(R.string.apply_now)) }
        }
    }

    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Hero(condition: Condition, state: UiState) {
        val ready = condition == Condition.READY
        val container by animateColorAsState(
            when (condition) {
                Condition.READY -> MaterialTheme.colorScheme.primaryContainer
                Condition.NO_PRIVILEGE, Condition.RESTRICTED, Condition.ATTENTION -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.surface
            },
            MaterialTheme.motionScheme.defaultEffectsSpec(),
            label = "container",
        )
        val rotation by animateFloatAsState(if (ready) 45f else 0f, MaterialTheme.motionScheme.slowSpatialSpec(), label = "rotation")
        val busy = state.operation != null || condition == Condition.PREPARING || condition == Condition.CHECKING
        Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.extraLarge, color = container) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(Modifier.size(88.dp), contentAlignment = Alignment.Center) {
                    if (busy) {
                        ContainedLoadingIndicator(Modifier.size(88.dp))
                    } else {
                        Box(
                            Modifier.size(88.dp).rotate(rotation).clip(MaterialShapes.Cookie9Sided.toShape()).background(
                                if (ready) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                            ),
                        )
                        Icon(
                            if (ready) Icons.Default.VerifiedUser else Icons.Default.Warning,
                            null,
                            tint = if (ready) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.surface,
                            modifier = Modifier.size(40.dp),
                        )
                    }
                }
                Text(stringResource(title(condition)), style = MaterialTheme.typography.headlineSmall)
                Text(stringResource(description(condition)), style = MaterialTheme.typography.bodyLarge)
            }
        }
    }

    fun title(condition: Condition): Int = when (condition) {
        Condition.PREPARING -> R.string.hero_preparing
        Condition.NO_PRIVILEGE -> R.string.hero_no_privilege
        Condition.RESTRICTED -> R.string.hero_restricted
        Condition.CHECKING -> R.string.hero_checking
        Condition.NOT_SET_UP -> R.string.hero_not_set_up
        Condition.READY -> R.string.hero_ready
        Condition.ATTENTION -> R.string.hero_attention
    }

    fun description(condition: Condition): Int = when (condition) {
        Condition.PREPARING -> R.string.hero_preparing_text
        Condition.NO_PRIVILEGE -> R.string.hero_no_privilege_text
        Condition.RESTRICTED -> R.string.hero_restricted_text
        Condition.CHECKING -> R.string.hero_checking_text
        Condition.NOT_SET_UP -> R.string.hero_not_set_up_text
        Condition.READY -> R.string.hero_ready_text
        Condition.ATTENTION -> R.string.hero_attention_text
    }

    /** Guides the user to a privilege: what each candidate says, and what to do. */
    @Composable
    fun Setup(selection: PrivilegeSelection, onGrant: () -> Unit, onRecheck: () -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Widgets.Header(stringResource(R.string.setup_title))
            Widgets.Group {
                selection.statuses.forEachIndexed { index, (kind, status) ->
                    Widgets.Item(
                        index = index,
                        count = selection.statuses.size,
                        headline = Labels.privilege(kind),
                        supporting = Labels.describe(status),
                        icon = Icons.Default.AdminPanelSettings,
                        trailing = if (status == PrivilegeStatus.PermissionRequired) {
                            { FilledTonalButton(onClick = onGrant) { Text(stringResource(R.string.grant)) } }
                        } else {
                            null
                        },
                    )
                }
            }
            Text(stringResource(R.string.setup_help), style = MaterialTheme.typography.bodyMedium, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))
            TextButton(onClick = onRecheck) { Text(stringResource(R.string.check_again)) }
        }
    }

    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Actions(state: UiState, condition: Condition, settings: Settings.Values, model: AppViewModel) {
        val idle = state.ready && state.operation == null && state.privilege?.privilege != null && condition != Condition.RESTRICTED
        val height = ButtonDefaults.MediumContainerHeight
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = model::refresh,
                    enabled = idle,
                    shapes = ButtonDefaults.shapes(),
                    contentPadding = ButtonDefaults.contentPaddingFor(height),
                    modifier = Modifier.weight(1f).heightIn(min = height),
                ) {
                    Icon(Icons.Default.Refresh, null, Modifier.size(ButtonDefaults.iconSizeFor(height)))
                    Spacer(Modifier.size(ButtonDefaults.iconSpacingFor(height)))
                    Text(stringResource(if (settings.applied) R.string.action_refresh else R.string.action_set_up), style = ButtonDefaults.textStyleFor(height))
                }
                FilledTonalButton(
                    onClick = model::repair,
                    enabled = idle && state.status != null,
                    shapes = ButtonDefaults.shapes(),
                    contentPadding = ButtonDefaults.contentPaddingFor(height),
                    modifier = Modifier.weight(1f).heightIn(min = height),
                ) {
                    Icon(Icons.Default.Build, null, Modifier.size(ButtonDefaults.iconSizeFor(height)))
                    Spacer(Modifier.size(ButtonDefaults.iconSpacingFor(height)))
                    Text(stringResource(R.string.action_repair), style = ButtonDefaults.textStyleFor(height))
                }
            }
            Text(
                stringResource(if (settings.applied) R.string.actions_help else R.string.actions_help_first),
                style = MaterialTheme.typography.bodySmall,
                color = Widgets.secondary,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
    }

    @Composable
    fun Outcome(outcome: Outcome, onLog: () -> Unit, onDismiss: () -> Unit) {
        val dismiss: @Composable () -> Unit = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.dismiss)) } }
        val logButton: @Composable () -> Unit = { TextButton(onClick = onLog) { Text(stringResource(R.string.show_log)) } }
        when (outcome) {
            is Outcome.Refreshed -> {
                val refreshed = outcome.refreshed
                val lines = buildList {
                    refreshed.keybox?.let { add(stringResource(if (it.changed) R.string.outcome_keybox_new else R.string.outcome_keybox_same)) }
                    refreshed.fingerprint?.let { add(stringResource(if (it.changed) R.string.outcome_fingerprint_new else R.string.outcome_fingerprint_same)) }
                    add(applySummary(refreshed.apply.targets, refreshed.apply.staleKeysRemoved, refreshed.apply.daemonRestarted))
                    refreshed.problems.forEach { add(it) }
                }
                val tone = if (refreshed.problems.isEmpty()) Widgets.Tone.INFORMATION else Widgets.Tone.WARNING
                val title = stringResource(if (refreshed.problems.isEmpty()) R.string.outcome_refreshed else R.string.outcome_refreshed_problems)
                Widgets.Notice(tone, title, lines.joinToString("\n")) {
                    logButton()
                    dismiss()
                }
            }
            is Outcome.Repaired -> Widgets.Notice(
                Widgets.Tone.INFORMATION,
                stringResource(R.string.outcome_repaired),
                applySummary(outcome.repaired.apply.targets, outcome.repaired.apply.staleKeysRemoved, outcome.repaired.restarted),
            ) {
                logButton()
                dismiss()
            }
            is Outcome.Installed -> Widgets.Notice(
                Widgets.Tone.INFORMATION,
                stringResource(R.string.outcome_installed),
                stringResource(R.string.outcome_installed_text) + "\n" + applySummary(outcome.repaired.apply.targets, outcome.repaired.apply.staleKeysRemoved, outcome.repaired.restarted),
            ) {
                logButton()
                dismiss()
            }
            is Outcome.Restarted -> Widgets.Notice(
                if (outcome.restarted) Widgets.Tone.INFORMATION else Widgets.Tone.WARNING,
                stringResource(R.string.outcome_restarted),
                stringResource(if (outcome.restarted) R.string.outcome_restarted_text else R.string.outcome_not_restarted_text),
            ) {
                logButton()
                dismiss()
            }
            is Outcome.ModuleInstalled -> Widgets.Notice(Widgets.Tone.INFORMATION, stringResource(R.string.outcome_module), stringResource(R.string.outcome_module_text)) {
                logButton()
                dismiss()
            }
            is Outcome.Failed -> Widgets.Notice(Widgets.Tone.ERROR, stringResource(R.string.outcome_failed), outcome.text) {
                logButton()
                dismiss()
            }
        }
    }

    @Composable
    fun applySummary(targets: Int, staleKeys: Int, restarted: Boolean): String = listOf(
        pluralStringResource(R.plurals.summary_targets, targets, targets),
        pluralStringResource(R.plurals.summary_stale_removed, staleKeys, staleKeys),
        stringResource(if (restarted) R.string.summary_restarted else R.string.summary_not_restarted),
    ).joinToString("\n")

    @Composable
    fun tint(level: Level): Color = when (level) {
        Level.OK -> MaterialTheme.colorScheme.primary
        Level.WARNING -> MaterialTheme.colorScheme.tertiary
        Level.ERROR -> MaterialTheme.colorScheme.error
        Level.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    fun icon(level: Level): ImageVector = when (level) {
        Level.OK -> Icons.Default.CheckCircle
        Level.WARNING -> Icons.Default.Warning
        Level.ERROR -> Icons.Default.Error
        Level.NEUTRAL -> Icons.Default.Schedule
    }

    /** One line of the checklist. */
    data class Check(val icon: ImageVector, val level: Level, val headline: String, val supporting: String, val destination: ReplayApp.Destination?)

    /** Every piece that STRONG needs, how it stands, and where to look at it. */
    @Composable
    fun Checklist(status: StatusReport, settings: Settings.Values, onNavigate: (ReplayApp.Destination) -> Unit) {
        val checks = buildList {
            Component.entries.forEach { component -> add(componentCheck(component, status.component(component))) }
            add(zygiskCheck(status))
            add(keyboxCheck(status.keybox))
            add(fingerprintCheck(status))
            add(spoofCheck(status))
            add(keysCheck(status))
            add(daemonCheck(status))
            if (status.conflicts.isNotEmpty() || status.rootManagers.size > 1) add(conflictCheck(status))
            add(bootCheck(status, settings))
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Widgets.Header(stringResource(R.string.checklist_title))
            Widgets.Group {
                checks.forEachIndexed { index, check ->
                    Widgets.Item(
                        index,
                        checks.size,
                        headline = check.headline,
                        supporting = check.supporting,
                        icon = check.icon,
                        trailing = { Icon(icon(check.level), null, tint = tint(check.level)) },
                        onClick = check.destination?.let { destination -> { onNavigate(destination) } },
                    )
                }
            }
        }
    }

    @Composable
    fun componentCheck(component: Component, state: ComponentState?): Check {
        val module = state?.module
        val (level, text) = when {
            module == null -> Level.ERROR to stringResource(R.string.component_missing, Labels.moduleName(component))
            state.flavor == Flavor.OTHER -> Level.ERROR to stringResource(R.string.component_other, module.name ?: module.id, Labels.moduleName(component))
            module.disabled -> Level.ERROR to stringResource(R.string.component_disabled)
            module.removing -> Level.ERROR to stringResource(R.string.component_removing)
            module.updatePending || !module.installed -> Level.WARNING to stringResource(R.string.component_update_pending, module.version ?: "?")
            else -> Level.OK to stringResource(R.string.component_installed, module.name ?: module.id, module.version ?: "?")
        }
        return Check(Icons.Default.Extension, level, Labels.component(component), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun zygiskCheck(status: StatusReport): Check {
        val zygisk = status.zygisk
        val (level, text) = when {
            zygisk == null -> Level.ERROR to stringResource(R.string.zygisk_no_manager)
            zygisk.modules.isNotEmpty() -> Level.OK to stringResource(R.string.zygisk_module, zygisk.modules.joinToString(", "))
            zygisk.magiskBuiltin == true -> Level.OK to stringResource(R.string.zygisk_builtin)
            else -> Level.ERROR to stringResource(R.string.zygisk_missing)
        }
        return Check(Icons.Default.Memory, level, stringResource(R.string.check_zygisk), text, null)
    }

    @Composable
    fun keyboxCheck(keybox: KeyboxVerdict?): Check {
        val (level, text) = when {
            keybox == null -> Level.ERROR to stringResource(R.string.keybox_none)
            keybox.revoked -> Level.ERROR to stringResource(R.string.keybox_revoked)
            !keybox.strongCapable -> Level.ERROR to stringResource(R.string.keybox_weak, keybox.usableKeys, keybox.keys.size)
            !keybox.revocationChecked -> Level.WARNING to stringResource(R.string.keybox_unchecked)
            else -> Level.OK to (keybox.expires?.let { stringResource(R.string.keybox_valid_until, Labels.date(it)) } ?: stringResource(R.string.keybox_valid))
        }
        return Check(Icons.Default.Key, level, stringResource(R.string.check_keybox), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun fingerprintCheck(status: StatusReport): Check {
        val fingerprint = status.fingerprint
        val (level, text) = when {
            fingerprint == null -> Level.ERROR to stringResource(R.string.fingerprint_none)
            !fingerprint.ok -> Level.ERROR to fingerprint.problems.map { Labels.problem(it) }.joinToString(", ")
            else -> Level.OK to listOfNotNull(
                stringResource(R.string.fingerprint_model, fingerprint.model ?: "?", fingerprint.device ?: "?"),
                fingerprint.securityPatch?.let { stringResource(R.string.fingerprint_patch, it) },
                fingerprint.expires?.let { stringResource(R.string.fingerprint_expires, Labels.date(it)) },
            ).joinToString(" · ")
        }
        return Check(Icons.Default.Fingerprint, level, stringResource(R.string.check_fingerprint), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun spoofCheck(status: StatusReport): Check {
        val drifted = status.driftedSpoof()
        val (level, text) = when {
            status.integrity == null -> Level.WARNING to stringResource(R.string.spoof_not_written)
            drifted.isNotEmpty() -> Level.WARNING to stringResource(R.string.spoof_drifted, drifted.joinToString(", "))
            else -> Level.OK to stringResource(R.string.spoof_applied)
        }
        return Check(Icons.Default.Tune, level, stringResource(R.string.check_spoof), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun keysCheck(status: StatusReport): Check {
        val stale = status.staleKeys.size
        val (level, text) = when {
            stale > 0 -> Level.WARNING to pluralStringResource(R.plurals.keys_stale, stale, stale, status.persistedKeys)
            else -> Level.OK to pluralStringResource(R.plurals.keys_current, status.persistedKeys, status.persistedKeys)
        }
        return Check(Icons.Default.Key, level, stringResource(R.string.check_keys), text, null)
    }

    @Composable
    fun daemonCheck(status: StatusReport): Check {
        val running = status.daemon.running
        val text = if (running) stringResource(R.string.daemon_running, status.daemon.daemons.joinToString(", ")) else stringResource(R.string.daemon_stopped)
        return Check(Icons.Default.Memory, if (running) Level.OK else Level.WARNING, stringResource(R.string.check_daemon), text, null)
    }

    @Composable
    fun conflictCheck(status: StatusReport): Check {
        val texts = buildList {
            if (status.rootManagers.size > 1) add(stringResource(R.string.conflict_managers, Labels.rootManagers(status.rootManagers)))
            status.conflicts.forEach { add(stringResource(R.string.conflict_module, it.name ?: it.id, it.id)) }
        }
        return Check(Icons.Default.Warning, Level.ERROR, stringResource(R.string.check_conflicts), texts.joinToString("\n"), null)
    }

    @Composable
    fun bootCheck(status: StatusReport, settings: Settings.Values): Check {
        val hook = status.bootHook
        val (level, text) = when {
            settings.bootHook && hook.installed ->
                Level.OK to (status.bootedAt?.let { stringResource(R.string.boot_hook_ran, Labels.rootManagers(hook.managers), Labels.dateTime(it)) }
                    ?: stringResource(R.string.boot_hook_installed, Labels.rootManagers(hook.managers)))
            settings.bootHook && hook.managers.isEmpty() -> Level.WARNING to stringResource(R.string.boot_hook_unsupported)
            settings.bootHook && settings.applied -> Level.WARNING to stringResource(R.string.boot_hook_pending)
            settings.repairAfterBoot -> Level.NEUTRAL to stringResource(R.string.boot_application_only)
            else -> Level.WARNING to stringResource(R.string.boot_off)
        }
        return Check(Icons.Default.PowerSettingsNew, level, stringResource(R.string.check_boot), text, ReplayApp.Destination.SETTINGS)
    }

    @Composable
    fun Details(state: UiState, settings: Settings.Values, onSettings: () -> Unit, onLog: () -> Unit) {
        val status = state.status
        val items = buildList<@Composable (Int, Int) -> Unit> {
            add { index, count ->
                val selected = state.privilege?.privilege
                Widgets.Item(
                    index, count,
                    headline = stringResource(R.string.detail_privilege),
                    supporting = selected?.let { stringResource(R.string.privilege_runs_as_root, Labels.privilege(it.kind)) } ?: stringResource(R.string.privilege_none_short),
                    icon = Icons.Default.AdminPanelSettings,
                    onClick = onSettings,
                )
            }
            add { index, count ->
                val managers = status?.rootManagers.orEmpty()
                Widgets.Item(
                    index, count,
                    headline = stringResource(R.string.detail_root_manager),
                    supporting = if (managers.isEmpty()) stringResource(R.string.unknown) else Labels.rootManagers(managers),
                    icon = Icons.Default.AdminPanelSettings,
                )
            }
            add { index, count ->
                val last = settings.lastRefreshAt
                Widgets.Item(
                    index, count,
                    headline = stringResource(R.string.detail_last_refresh),
                    supporting = when {
                        last == null -> stringResource(R.string.never)
                        settings.lastRefreshProblems.isEmpty() -> Labels.relative(last)
                        else -> stringResource(R.string.last_refresh_problems, Labels.relative(last), settings.lastRefreshProblems.size)
                    } + "\n" + if (settings.refreshHours == 0) stringResource(R.string.refresh_off) else stringResource(R.string.refresh_every, settings.refreshHours),
                    icon = Icons.Default.Schedule,
                    onClick = onSettings,
                )
            }
            status?.appliedAt?.let { applied ->
                add { index, count -> Widgets.Item(index, count, stringResource(R.string.detail_last_apply), Labels.dateTime(applied), Icons.Default.Build) }
            }
            if (state.log.isNotEmpty()) add { index, count ->
                Widgets.Item(index, count, stringResource(R.string.log), pluralStringResource(R.plurals.log_lines, state.log.size, state.log.size), Icons.AutoMirrored.Filled.Notes, onClick = onLog)
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Widgets.Header(stringResource(R.string.details_title))
            Widgets.Group { items.forEachIndexed { index, item -> item(index, items.size) } }
        }
    }

    /** What the device itself is, as the application sees it (Play services see the spoofed build instead). */
    @Composable
    fun Device(firstApiLevel: Int?) {
        val rows = listOf(
            stringResource(R.string.device_model) to "${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})",
            stringResource(R.string.device_android) to stringResource(R.string.device_android_value, Build.VERSION.RELEASE, Build.VERSION.SDK_INT),
            stringResource(R.string.device_patch) to Build.VERSION.SECURITY_PATCH,
            stringResource(R.string.device_first_api) to (firstApiLevel?.toString() ?: stringResource(R.string.unknown)),
            stringResource(R.string.device_fingerprint) to Build.FINGERPRINT,
        )
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Widgets.Header(stringResource(R.string.device_title))
            Widgets.Panel(0, 1) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(Icons.Default.PhoneAndroid, null, tint = Widgets.secondary)
                    Text(stringResource(R.string.device_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary)
                }
                rows.forEach { (label, value) -> Widgets.Field(label, value, monospace = label == rows.last().first) }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun Log(lines: List<LogLine>, onDismiss: () -> Unit) {
        ModalBottomSheet(onDismissRequest = onDismiss, containerColor = MaterialTheme.colorScheme.surfaceContainer) {
            Text(stringResource(R.string.log), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
            if (lines.isEmpty()) Text(stringResource(R.string.log_empty), modifier = Modifier.padding(24.dp))
            LazyColumn(contentPadding = PaddingValues(start = 24.dp, end = 24.dp, bottom = 32.dp)) {
                items(lines) { line ->
                    Text(
                        "${Labels.dateTime(line.time)}  ${line.message}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = when (line.level) {
                            LogLevel.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
                            LogLevel.WARNING -> MaterialTheme.colorScheme.tertiary
                            LogLevel.ERROR -> MaterialTheme.colorScheme.error
                        },
                        modifier = Modifier.padding(vertical = 2.dp),
                    )
                }
            }
        }
    }
}
