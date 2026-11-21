package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircleOutline
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.RemoveCircleOutline
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shop
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Target
import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.engine.TargetScope
import dev.nercone.replayintegrity.ui.Notices.notices

/** The applications whose keys TEESimulator-RS attests, and the rules that shape the list. */
object TargetsScreen {
    /** The Play stack, which is always a target (`TargetList::ALWAYS` of the engine). */
    val ALWAYS = setOf("com.google.android.gms", "com.google.android.gsf", "com.android.vending")

    /** A package name as the package manager accepts it (`Target::is_package_name` of the engine). */
    val PACKAGE = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    @Composable
    fun Content(state: UiState, settings: Settings.Values, model: AppViewModel) {
        LaunchedEffect(Unit) { model.loadApps() }
        var query by rememberSaveable { mutableStateOf("") }
        val targets = state.status?.targets?.targets.orEmpty()
        val shown = targets.filter { target ->
            query.isBlank() || target.packageName.contains(query, ignoreCase = true) || state.apps?.get(target.packageName)?.label?.contains(query, ignoreCase = true) == true
        }
        // The targets form one segmented group, so the list keeps the gap of such a group and
        // the items above it add the rest of the usual spacing.
        val gap = ListItemDefaults.SegmentedGap
        val extra = Widgets.SPACING - gap
        Widgets.Screen(spacing = gap) {
            notices(state, settings, model, extra)
            item(key = "rules") { Box(Modifier.padding(bottom = extra)) { Rules(settings, model) } }
            item(key = "header") {
                Column(Modifier.padding(bottom = extra), verticalArrangement = Arrangement.spacedBy(Widgets.SPACING)) {
                    Widgets.Header(pluralStringResource(R.plurals.targets_current, targets.size, targets.size))
                    if (state.status?.targets == null) {
                        Widgets.Help(stringResource(R.string.targets_none))
                    } else {
                        OutlinedTextField(
                            query,
                            { query = it },
                            label = { Text(stringResource(R.string.search)) },
                            leadingIcon = { Icon(Icons.Default.Search, null) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            }
            itemsIndexed(shown, key = { _, target -> target.packageName }) { index, target -> TargetItem(index, shown.size, target, state.apps, model) }
        }
    }

    /** The rules that decide the list: which applications, how their keys are handled, and the packages added or left out. */
    @Composable
    fun Rules(settings: Settings.Values, model: AppViewModel) {
        Widgets.Section(stringResource(R.string.targets_rules)) {
            Widgets.ChoiceItem(
                0, 5,
                headline = stringResource(R.string.targets_scope),
                options = TargetScope.entries,
                selected = settings.targetScope,
                describe = { Labels.targetScope(it) },
                onSelect = { scope -> model.configure { it.copy(targetScope = scope) } },
                icon = Icons.Default.Apps,
                description = stringResource(R.string.targets_scope_help),
            )
            Widgets.ChoiceItem(
                1, 5,
                headline = stringResource(R.string.targets_mode),
                options = TargetMode.entries,
                selected = settings.targetMode,
                describe = { Labels.targetMode(it) },
                onSelect = { mode -> model.configure { it.copy(targetMode = mode) } },
                icon = Icons.Default.Key,
                description = stringResource(R.string.targets_mode_help),
            )
            Widgets.ChoiceItem(
                2, 5,
                headline = stringResource(R.string.targets_play_mode),
                options = TargetMode.entries,
                selected = settings.playTargetMode,
                describe = { Labels.targetMode(it) },
                onSelect = { mode -> model.configure { it.copy(playTargetMode = mode) } },
                icon = Icons.Default.Shop,
                description = stringResource(R.string.targets_play_mode_help),
            )
            Widgets.StringListItem(
                3, 5,
                headline = stringResource(R.string.targets_extra),
                items = settings.extraPackages,
                label = stringResource(R.string.settings_package),
                help = stringResource(R.string.targets_extra_help),
                validate = { PACKAGE.matches(it) },
                onAdd = { name -> model.configure { it.copy(extraPackages = (it.extraPackages + name).distinct()) } },
                onRemove = { name -> model.configure { it.copy(extraPackages = it.extraPackages - name) } },
                icon = Icons.Default.AddCircleOutline,
            )
            Widgets.StringListItem(
                4, 5,
                headline = stringResource(R.string.targets_excluded),
                items = settings.excludedPackages,
                label = stringResource(R.string.settings_package),
                help = stringResource(R.string.targets_excluded_help),
                validate = { PACKAGE.matches(it) && it !in ALWAYS },
                onAdd = { name -> model.configure { it.copy(excludedPackages = (it.excludedPackages + name).distinct()) } },
                onRemove = { name -> model.configure { it.copy(excludedPackages = it.excludedPackages - name) } },
                icon = Icons.Default.RemoveCircleOutline,
            )
        }
    }

    @Composable
    fun TargetItem(index: Int, count: Int, target: Target, apps: Map<String, InstalledApp>?, model: AppViewModel) {
        val app = apps?.get(target.packageName)
        val always = target.packageName in ALWAYS
        Widgets.Item(
            index, count,
            headline = app?.label ?: target.packageName,
            supporting = listOfNotNull(
                target.packageName.takeIf { app != null },
                Labels.targetMode(target.mode),
                stringResource(R.string.target_system).takeIf { app?.system == true },
                stringResource(R.string.target_not_installed).takeIf { apps != null && app == null },
            ).joinToString(" · "),
            icon = if (always) Icons.Default.Lock else Icons.Default.Android,
            trailing = if (always) {
                null
            } else {
                { IconButton(onClick = { model.exclude(target.packageName, true) }) { Icon(Icons.Default.Block, stringResource(R.string.target_exclude)) } }
            },
        )
    }
}
