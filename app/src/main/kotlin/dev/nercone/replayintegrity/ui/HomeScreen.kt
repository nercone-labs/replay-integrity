package dev.nercone.replayintegrity.ui

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.ui.Notices.notices

/**
 * The home screen: the verdict with the actions, a checklist of every piece STRONG needs, and
 * the details. In a wide window the checklist stands beside the verdict.
 */
object HomeScreen {
    /** The state of the device, as the verdict tells it. */
    enum class Condition { PREPARING, NO_PRIVILEGE, UNREADABLE, RESTRICTED, CHECKING, NOT_SET_UP, READY, ATTENTION }

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
    fun Content(data: ScreenData, model: AppViewModel, navigator: ReplayApp.Navigator) {
        val state = data.state
        val settings = data.settings
        val condition = condition(state, settings)
        val status = state.status
        Widgets.Screen(columnsWidth = 1100.dp) { width ->
            notices(data, model)
            val main: @Composable () -> Unit = {
                Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
                    Verdict(condition, state, settings, model)
                    if (condition == Condition.NO_PRIVILEGE) state.privilege?.let { Privileges.Setup(it, onGrant = model::grantShizuku, onRecheck = model::recheck) }
                    Details(state, settings, model, onSettings = { page -> navigator.open(ReplayApp.Destination.SETTINGS, page) })
                }
            }
            val side: @Composable () -> Unit = {
                Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
                    if (status != null) Checklist.Content(status, settings, navigator)
                    Device(status?.firstApiLevel)
                }
            }
            if (width >= Widgets.TWO_COLUMNS) {
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
    @Composable
    fun Verdict(condition: Condition, state: UiState, settings: Settings.Values, model: AppViewModel) {
        val mood = mood(condition)
        val actions = actions(condition, state, settings, model)
        Widgets.Hero(
            mood = mood,
            busy = state.operation != null || condition == Condition.PREPARING || condition == Condition.CHECKING,
            title = stringResource(title(condition)),
            text = state.operation?.let { Labels.operation(it) } ?: stringResource(description(condition)),
            detail = state.statusError?.takeIf { condition == Condition.UNREADABLE }?.text,
            actions = actions,
            help = if (actions.size > 1) stringResource(if (settings.applied) R.string.actions_help else R.string.actions_help_first) else null,
        ) { color ->
            Icon(if (mood == Widgets.Mood.GOOD) Icons.Default.VerifiedUser else Icons.Default.Warning, null, tint = color, modifier = Modifier.size(36.dp))
        }
    }

    fun mood(condition: Condition): Widgets.Mood = when (condition) {
        Condition.READY -> Widgets.Mood.GOOD
        Condition.NO_PRIVILEGE, Condition.RESTRICTED, Condition.ATTENTION, Condition.UNREADABLE -> Widgets.Mood.BAD
        Condition.PREPARING, Condition.CHECKING, Condition.NOT_SET_UP -> Widgets.Mood.NEUTRAL
    }

    @Composable
    fun actions(condition: Condition, state: UiState, settings: Settings.Values, model: AppViewModel): List<Widgets.Action> = when (condition) {
        Condition.NO_PRIVILEGE, Condition.PREPARING -> emptyList()
        Condition.UNREADABLE, Condition.RESTRICTED -> listOf(Widgets.Action(stringResource(R.string.check_again), Icons.Default.Refresh, state.operation == null, model::recheck))
        else -> listOf(
            Widgets.Action(stringResource(if (settings.applied) R.string.action_refresh else R.string.action_set_up), Icons.Default.Refresh, state.idle, model::refresh),
            Widgets.Action(stringResource(R.string.action_repair), Icons.Default.Build, state.idle && state.status != null, model::repair),
        )
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

    @Composable
    fun Details(state: UiState, settings: Settings.Values, model: AppViewModel, onSettings: (SettingsScreen.Page) -> Unit) {
        val status = state.status
        val items = buildList<@Composable (Int, Int) -> Unit> {
            add { index, count ->
                val managers = status?.rootManagers.orEmpty()
                Widgets.Item(
                    index, count,
                    headline = stringResource(R.string.detail_privilege),
                    supporting = listOfNotNull(
                        Privileges.current(state.privilege),
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
