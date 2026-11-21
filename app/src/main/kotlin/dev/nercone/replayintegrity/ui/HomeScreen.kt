package dev.nercone.replayintegrity.ui

import android.os.Build
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeStatus
import dev.nercone.replayintegrity.ui.Notices.notices

/**
 * The home screen: the verdict with the actions, a checklist of every piece STRONG needs, and
 * the details. In a wide window the checklist stands beside the verdict.
 */
object HomeScreen {
    /** The state of the device, as the verdict tells it. */
    enum class Condition { PREPARING, NO_PRIVILEGE, UNREADABLE, RESTRICTED, CHECKING, NOT_SET_UP, READY, ATTENTION }

    /** The width from which the checklist stands beside the verdict. */
    val TWO_COLUMNS = 840.dp

    fun condition(state: UiState, settings: Settings.Values): Condition = when {
        !state.ready -> Condition.PREPARING
        state.privilege != null && state.privilege.privilege == null -> Condition.NO_PRIVILEGE
        state.statusError?.restricted == true -> Condition.RESTRICTED
        state.statusError != null -> Condition.UNREADABLE
        state.status == null -> Condition.CHECKING
        state.status.missingCapabilities.isNotEmpty() -> Condition.RESTRICTED
        state.status.strongReady -> Condition.READY
        !settings.applied -> Condition.NOT_SET_UP
        else -> Condition.ATTENTION
    }

    @Composable
    fun Content(state: UiState, settings: Settings.Values, model: AppViewModel, navigator: ReplayApp.Navigator) {
        val condition = condition(state, settings)
        val status = state.status
        Widgets.Screen(maxWidth = 1100.dp) { width ->
            notices(state, settings, model)
            val main: @Composable () -> Unit = {
                Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
                    Verdict(condition, state, settings, model)
                    if (condition == Condition.NO_PRIVILEGE) state.privilege?.let { Setup(it, onGrant = model::grantShizuku, onRecheck = model::recheck) }
                    Details(state, settings, model, onSettings = { page -> navigator.open(ReplayApp.Destination.SETTINGS, page) })
                }
            }
            val side: @Composable () -> Unit = {
                Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
                    if (status != null) Checklist.Content(status, settings, navigator)
                    Device(status?.firstApiLevel)
                }
            }
            if (width >= TWO_COLUMNS) {
                item(key = "columns") {
                    Row(horizontalArrangement = Arrangement.spacedBy(Widgets.SCREEN_PADDING)) {
                        Box(Modifier.weight(1f)) { main() }
                        Box(Modifier.weight(1f)) { side() }
                    }
                }
            } else {
                item(key = "main") { main() }
                item(key = "side") { side() }
            }
        }
    }

    /** The verdict: how the device stands, what to do about it, and the actions that do it. */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Verdict(condition: Condition, state: UiState, settings: Settings.Values, model: AppViewModel) {
        val ready = condition == Condition.READY
        val failing = condition == Condition.NO_PRIVILEGE || condition == Condition.RESTRICTED || condition == Condition.ATTENTION || condition == Condition.UNREADABLE
        val container by animateColorAsState(
            when {
                ready -> MaterialTheme.colorScheme.primaryContainer
                failing -> MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.surface
            },
            MaterialTheme.motionScheme.defaultEffectsSpec(),
            label = "container",
        )
        val rotation by animateFloatAsState(if (ready) 45f else 0f, MaterialTheme.motionScheme.slowSpatialSpec(), label = "rotation")
        val busy = state.operation != null || condition == Condition.PREPARING || condition == Condition.CHECKING
        Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.extraLarge, color = container) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Box(Modifier.size(72.dp), contentAlignment = Alignment.Center) {
                        if (busy) {
                            ContainedLoadingIndicator(Modifier.size(72.dp))
                        } else {
                            Box(
                                Modifier.size(72.dp).rotate(rotation).clip(MaterialShapes.Cookie9Sided.toShape()).background(
                                    if (ready) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                                ),
                            )
                            Icon(
                                if (ready) Icons.Default.VerifiedUser else Icons.Default.Warning,
                                null,
                                tint = if (ready) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.surface,
                                modifier = Modifier.size(36.dp),
                            )
                        }
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(title(condition)), style = MaterialTheme.typography.headlineSmall)
                        Text(
                            state.operation?.let { Labels.operation(it) } ?: stringResource(description(condition)),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                state.statusError?.takeIf { condition == Condition.UNREADABLE }?.let {
                    Text(it.text, style = MaterialTheme.typography.bodySmall)
                }
                Actions(condition, state, settings, model)
            }
        }
    }

    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Actions(condition: Condition, state: UiState, settings: Settings.Values, model: AppViewModel) {
        when (condition) {
            Condition.NO_PRIVILEGE, Condition.PREPARING -> return
            Condition.UNREADABLE, Condition.RESTRICTED -> {
                FilledTonalButton(onClick = model::recheck, enabled = state.operation == null) { Text(stringResource(R.string.check_again)) }
                return
            }
            else -> Unit
        }
        val height = ButtonDefaults.MediumContainerHeight
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ActionButton(
                    primary = true,
                    icon = Icons.Default.Refresh,
                    text = stringResource(if (settings.applied) R.string.action_refresh else R.string.action_set_up),
                    enabled = state.idle,
                    onClick = model::refresh,
                    modifier = Modifier.weight(1f).heightIn(min = height),
                )
                ActionButton(
                    primary = false,
                    icon = Icons.Default.Build,
                    text = stringResource(R.string.action_repair),
                    enabled = state.idle && state.status != null,
                    onClick = model::repair,
                    modifier = Modifier.weight(1f).heightIn(min = height),
                )
            }
            Text(stringResource(if (settings.applied) R.string.actions_help else R.string.actions_help_first), style = MaterialTheme.typography.bodySmall)
        }
    }

    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun ActionButton(primary: Boolean, icon: ImageVector, text: String, enabled: Boolean, onClick: () -> Unit, modifier: Modifier) {
        val height = ButtonDefaults.MediumContainerHeight
        val content: @Composable () -> Unit = {
            Icon(icon, null, Modifier.size(ButtonDefaults.iconSizeFor(height)))
            Spacer(Modifier.size(ButtonDefaults.iconSpacingFor(height)))
            Text(text, style = ButtonDefaults.textStyleFor(height))
        }
        if (primary) {
            Button(onClick = onClick, enabled = enabled, shapes = ButtonDefaults.shapes(), contentPadding = ButtonDefaults.contentPaddingFor(height), modifier = modifier) { content() }
        } else {
            FilledTonalButton(onClick = onClick, enabled = enabled, shapes = ButtonDefaults.shapes(), contentPadding = ButtonDefaults.contentPaddingFor(height), modifier = modifier) { content() }
        }
    }

    fun title(condition: Condition): Int = when (condition) {
        Condition.PREPARING -> R.string.hero_preparing
        Condition.NO_PRIVILEGE -> R.string.hero_no_privilege
        Condition.UNREADABLE -> R.string.hero_unreadable
        Condition.RESTRICTED -> R.string.hero_restricted
        Condition.CHECKING -> R.string.hero_checking
        Condition.NOT_SET_UP -> R.string.hero_not_set_up
        Condition.READY -> R.string.hero_ready
        Condition.ATTENTION -> R.string.hero_attention
    }

    fun description(condition: Condition): Int = when (condition) {
        Condition.PREPARING -> R.string.hero_preparing_text
        Condition.NO_PRIVILEGE -> R.string.hero_no_privilege_text
        Condition.UNREADABLE -> R.string.hero_unreadable_text
        Condition.RESTRICTED -> R.string.hero_restricted_text
        Condition.CHECKING -> R.string.hero_checking_text
        Condition.NOT_SET_UP -> R.string.hero_not_set_up_text
        Condition.READY -> R.string.hero_ready_text
        Condition.ATTENTION -> R.string.hero_attention_text
    }

    /** Guides the user to a privilege: what each candidate says, and what to do. */
    @Composable
    fun Setup(selection: PrivilegeSelection, onGrant: () -> Unit, onRecheck: () -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(stringResource(R.string.setup_title), stringResource(R.string.setup_help)) {
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
            FlowRow(Modifier.padding(horizontal = 8.dp)) { TextButton(onClick = onRecheck) { Text(stringResource(R.string.check_again)) } }
        }
    }

    @Composable
    fun Details(state: UiState, settings: Settings.Values, model: AppViewModel, onSettings: (SettingsScreen.Page) -> Unit) {
        val status = state.status
        val items = buildList<@Composable (Int, Int) -> Unit> {
            add { index, count ->
                val selected = state.privilege?.privilege
                val managers = status?.rootManagers.orEmpty()
                Widgets.Item(
                    index, count,
                    headline = stringResource(R.string.detail_privilege),
                    supporting = listOfNotNull(
                        selected?.let { stringResource(R.string.privilege_runs_as_root, Labels.privilege(it.kind)) } ?: stringResource(R.string.privilege_none_short),
                        managers.takeIf { it.isNotEmpty() }?.let { stringResource(R.string.detail_root_manager_value, Labels.rootManagers(it)) },
                    ).joinToString("\n"),
                    icon = Icons.Default.Security,
                    onClick = { onSettings(SettingsScreen.Page.PRIVILEGE) },
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
                    onClick = { onSettings(SettingsScreen.Page.REFRESH) },
                )
            }
            status?.appliedAt?.let { applied ->
                add { index, count -> Widgets.Item(index, count, stringResource(R.string.detail_last_apply), Labels.dateTime(applied), Icons.Default.Build) }
            }
            if (state.log.isNotEmpty()) add { index, count ->
                Widgets.Item(
                    index, count,
                    stringResource(R.string.log),
                    pluralStringResource(R.plurals.log_lines, state.log.size, state.log.size),
                    Icons.AutoMirrored.Filled.Notes,
                    onClick = { model.showLog(true) },
                )
            }
        }
        Widgets.Section(stringResource(R.string.details_title)) { items.forEachIndexed { index, item -> item(index, items.size) } }
    }

    /** What the device itself is, as the application sees it (Play services see the spoofed build instead). */
    @Composable
    fun Device(firstApiLevel: Int?) {
        Widgets.Section(stringResource(R.string.device_title), stringResource(R.string.device_help)) {
            Widgets.Panel(0, 1) {
                Widgets.Field(stringResource(R.string.device_model), "${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
                Widgets.Field(stringResource(R.string.device_android), stringResource(R.string.device_android_value, Build.VERSION.RELEASE, Build.VERSION.SDK_INT))
                Widgets.Field(stringResource(R.string.device_patch), Build.VERSION.SECURITY_PATCH)
                Widgets.Field(stringResource(R.string.device_first_api), firstApiLevel?.toString() ?: stringResource(R.string.unknown))
                Widgets.Field(stringResource(R.string.device_fingerprint), Build.FINGERPRINT, monospace = true)
            }
        }
    }
}
