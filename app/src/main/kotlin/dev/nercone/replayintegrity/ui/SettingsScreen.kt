package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material3.RadioButtonDefaults
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.privilege.PrivilegeChoice

object SettingsScreen {
    @Composable
    fun Content(settings: Settings.Values, model: AppViewModel) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Widgets.Section(stringResource(R.string.setting_privilege)) {
                PrivilegeOption(stringResource(R.string.setting_privilege_automatic), settings.privilege == PrivilegeChoice.AUTOMATIC) { model.setPrivilege(PrivilegeChoice.AUTOMATIC) }
                PrivilegeOption(stringResource(R.string.setting_privilege_shizuku), settings.privilege == PrivilegeChoice.SHIZUKU) { model.setPrivilege(PrivilegeChoice.SHIZUKU) }
                PrivilegeOption(stringResource(R.string.setting_privilege_root), settings.privilege == PrivilegeChoice.ROOT) { model.setPrivilege(PrivilegeChoice.ROOT) }
            }
            Widgets.Section(stringResource(R.string.tab_home)) {
                Widgets.SwitchRow(
                    stringResource(R.string.setting_auto_keybox),
                    stringResource(R.string.setting_auto_keybox_detail),
                    settings.autoKeybox,
                    onChange = model::setAutoKeybox,
                )
                Widgets.SwitchRow(
                    stringResource(R.string.setting_auto_fingerprint),
                    stringResource(R.string.setting_auto_fingerprint_detail),
                    settings.autoFingerprint,
                    onChange = model::setAutoFingerprint,
                )
                Widgets.SwitchRow(
                    stringResource(R.string.setting_boot_hook),
                    stringResource(R.string.setting_boot_hook_detail),
                    settings.bootHook,
                    onChange = model::setBootHook,
                )
            }
            Text(
                stringResource(R.string.setting_about),
                style = MaterialTheme.typography.bodySmall,
                color = Widgets.secondary,
                modifier = Modifier.padding(horizontal = 12.dp),
            )
        }
    }

    @Composable
    fun PrivilegeOption(label: String, selected: Boolean, onSelect: () -> Unit) {
        Row(
            Modifier.fillMaxWidth().selectable(selected = selected, onClick = onSelect).padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onSelect, modifier = Modifier.size(24.dp), colors = RadioButtonDefaults.colors())
            Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 16.dp))
        }
    }
}
