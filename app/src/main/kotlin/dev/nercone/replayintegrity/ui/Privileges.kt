package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeStatus

/** What the screens show of the privilege (`privilege` package): its words, the guide to get one, and the choice of it. */
object Privileges {
    @Composable
    fun label(kind: Privilege.Kind): String = stringResource(
        when (kind) {
            Privilege.Kind.ROOT -> R.string.privilege_root
            Privilege.Kind.SHIZUKU -> R.string.privilege_shizuku
            Privilege.Kind.SUI -> R.string.privilege_sui
        },
    )

    @Composable
    fun label(choice: PrivilegeChoice): String = stringResource(
        when (choice) {
            PrivilegeChoice.AUTOMATIC -> R.string.settings_privilege_automatic
            PrivilegeChoice.SHIZUKU -> R.string.settings_privilege_shizuku
            PrivilegeChoice.ROOT -> R.string.settings_privilege_root
        },
    )

    @Composable
    fun describe(status: PrivilegeStatus): String = when (status) {
        is PrivilegeStatus.Available -> stringResource(R.string.privilege_available)
        is PrivilegeStatus.InsufficientUser ->
            if (status.uid == Privilege.SHELL_UID) stringResource(R.string.privilege_shizuku_adb) else stringResource(R.string.privilege_wrong_user, status.uid)
        PrivilegeStatus.PermissionRequired -> stringResource(R.string.privilege_permission_required)
        is PrivilegeStatus.Unavailable -> stringResource(
            when (status.reason) {
                PrivilegeStatus.Reason.NOT_INSTALLED -> R.string.privilege_not_installed
                PrivilegeStatus.Reason.NOT_RUNNING -> R.string.privilege_not_running
                PrivilegeStatus.Reason.DENIED -> R.string.privilege_denied
                PrivilegeStatus.Reason.OUTDATED -> R.string.privilege_outdated
            },
        )
    }

    /** The privilege in use, in a line: through what the application runs as root, or that it cannot. */
    @Composable
    fun current(selection: PrivilegeSelection?): String =
        selection?.privilege?.let { stringResource(R.string.privilege_runs_as_root, label(it.kind)) } ?: stringResource(R.string.privilege_none_short)

    /** The choice and the privilege it selected, for the list of settings. */
    @Composable
    fun summary(choice: PrivilegeChoice, selection: PrivilegeSelection?): String =
        label(choice) + (selection?.privilege?.let { " · " + label(it.kind) } ?: "")

    /** Guides the user to a privilege: what each candidate says, and what to do. */
    @Composable
    fun Setup(selection: PrivilegeSelection, onGrant: () -> Unit, onRecheck: () -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
            Widgets.Section(stringResource(R.string.setup_title), stringResource(R.string.setup_help)) {
                selection.statuses.forEachIndexed { index, (kind, status) ->
                    Widgets.Item(
                        index = index,
                        count = selection.statuses.size,
                        headline = label(kind),
                        supporting = describe(status),
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

    /** The page of the settings that chooses the privilege, each choice with what it finds now. */
    @Composable
    fun Choices(selection: PrivilegeSelection?, choice: PrivilegeChoice, enabled: Boolean, onSelect: (PrivilegeChoice) -> Unit) {
        Widgets.Section(null, stringResource(R.string.settings_privilege_help)) {
            PrivilegeChoice.entries.forEachIndexed { index, entry ->
                Widgets.RadioItem(
                    index, PrivilegeChoice.entries.size,
                    headline = label(entry),
                    supporting = selection?.statuses?.let { statuses ->
                        when (entry) {
                            PrivilegeChoice.AUTOMATIC -> selection.privilege?.let { stringResource(R.string.privilege_runs_as_root, label(it.kind)) }
                            else -> statuses.firstOrNull { (kind, _) -> (kind == Privilege.Kind.ROOT) == (entry == PrivilegeChoice.ROOT) }
                                ?.let { (_, status) -> describe(status) }
                        }
                    },
                    selected = choice == entry,
                    enabled = enabled,
                ) { onSelect(entry) }
            }
        }
    }
}
