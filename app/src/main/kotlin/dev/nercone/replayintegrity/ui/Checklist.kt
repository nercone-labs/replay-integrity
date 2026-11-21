package dev.nercone.replayintegrity.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.ComponentState
import dev.nercone.replayintegrity.engine.Flavor
import dev.nercone.replayintegrity.engine.KeyboxVerdict
import dev.nercone.replayintegrity.engine.StatusReport

/** Every piece that STRONG needs, how it stands, and where to look at it. */
object Checklist {
    /** How a checklist item stands. */
    enum class Level { OK, WARNING, ERROR, NEUTRAL }

    /** One line of the checklist. */
    data class Check(
        val icon: ImageVector,
        val level: Level,
        val headline: String,
        val supporting: String,
        val destination: ReplayApp.Destination?,
        val page: SettingsScreen.Page? = null,
    )

    @Composable
    fun Content(status: StatusReport, settings: Settings.Values, onNavigate: (ReplayApp.Destination, SettingsScreen.Page?) -> Unit) {
        val checks = checks(status, settings)
        Widgets.Section(stringResource(R.string.checklist_title)) {
            checks.forEachIndexed { index, check ->
                Widgets.Item(
                    index,
                    checks.size,
                    headline = check.headline,
                    supporting = check.supporting,
                    icon = check.icon,
                    trailing = { Icon(icon(check.level), null, tint = tint(check.level)) },
                    onClick = check.destination?.let { destination -> { onNavigate(destination, check.page) } },
                )
            }
        }
    }

    /** The checks, the failing ones first, so that what keeps STRONG away is seen without scrolling. */
    @Composable
    fun checks(status: StatusReport, settings: Settings.Values): List<Check> = buildList {
        Component.entries.forEach { component -> add(component(component, status.component(component))) }
        add(zygisk(status))
        add(keybox(status.keybox))
        add(fingerprint(status))
        add(spoof(status))
        add(keys(status))
        add(daemon(status))
        if (status.conflicts.isNotEmpty() || status.rootManagers.size > 1) add(conflicts(status))
        add(boot(status, settings))
    }.sortedBy { if (it.level == Level.ERROR) 0 else 1 }

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

    @Composable
    fun component(component: Component, state: ComponentState?): Check {
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
    fun zygisk(status: StatusReport): Check {
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
    fun keybox(keybox: KeyboxVerdict?): Check {
        val (level, text) = when {
            keybox == null -> Level.ERROR to stringResource(R.string.keybox_none)
            keybox.defect != null -> Level.ERROR to stringResource(R.string.keybox_malformed)
            !keybox.strongCapable && keybox.revoked -> Level.ERROR to stringResource(R.string.keybox_revoked)
            !keybox.strongCapable -> Level.ERROR to stringResource(R.string.keybox_weak, keybox.usableKeys, keybox.keys.size)
            keybox.revoked -> Level.WARNING to stringResource(R.string.keybox_partly_revoked)
            !keybox.revocationChecked -> Level.WARNING to stringResource(R.string.keybox_unchecked)
            else -> Level.OK to (keybox.expires?.let { stringResource(R.string.keybox_valid_until, Labels.date(it)) } ?: stringResource(R.string.keybox_valid))
        }
        return Check(Icons.Default.Key, level, stringResource(R.string.check_keybox), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun fingerprint(status: StatusReport): Check {
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
    fun spoof(status: StatusReport): Check {
        val drifted = status.driftedSpoof()
        val (level, text) = when {
            status.integrity == null -> Level.WARNING to stringResource(R.string.spoof_not_written)
            drifted.isNotEmpty() -> Level.WARNING to stringResource(R.string.spoof_drifted, drifted.joinToString(", "))
            else -> Level.OK to stringResource(R.string.spoof_applied)
        }
        return Check(Icons.Default.Tune, level, stringResource(R.string.check_spoof), text, ReplayApp.Destination.ATTESTATION)
    }

    @Composable
    fun keys(status: StatusReport): Check {
        val stale = status.staleKeys.size
        val kept = status.keptKeys.size
        val (level, text) = when {
            stale > 0 -> Level.WARNING to pluralStringResource(R.plurals.keys_stale, stale, stale, status.persistedKeys)
            kept > 0 -> Level.NEUTRAL to pluralStringResource(R.plurals.keys_kept, kept, kept, status.persistedKeys)
            else -> Level.OK to pluralStringResource(R.plurals.keys_current, status.persistedKeys, status.persistedKeys)
        }
        return Check(Icons.Default.VpnKey, level, stringResource(R.string.check_keys), text, if (stale + kept > 0) ReplayApp.Destination.ATTESTATION else null)
    }

    @Composable
    fun daemon(status: StatusReport): Check {
        val running = status.daemon.running
        val text = if (running) stringResource(R.string.daemon_running, status.daemon.daemons.joinToString(", ")) else stringResource(R.string.daemon_stopped)
        return Check(Icons.Default.Memory, if (running) Level.OK else Level.WARNING, stringResource(R.string.check_daemon), text, null)
    }

    @Composable
    fun conflicts(status: StatusReport): Check {
        val texts = buildList {
            if (status.rootManagers.size > 1) add(stringResource(R.string.conflict_managers, Labels.rootManagers(status.rootManagers)))
            status.conflicts.forEach { add(stringResource(R.string.conflict_module, it.name ?: it.id, it.id)) }
        }
        return Check(Icons.Default.Warning, Level.ERROR, stringResource(R.string.check_conflicts), texts.joinToString("\n"), ReplayApp.Destination.ATTESTATION.takeIf { status.conflicts.isNotEmpty() })
    }

    @Composable
    fun boot(status: StatusReport, settings: Settings.Values): Check {
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
        return Check(Icons.Default.PowerSettingsNew, level, stringResource(R.string.check_boot), text, ReplayApp.Destination.SETTINGS, SettingsScreen.Page.APPLYING)
    }
}
