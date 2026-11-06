package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Target
import dev.nercone.replayintegrity.engine.TargetMode

/** The applications whose keys TEESimulator-RS attests, and the choices that shape the list. */
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
        LazyColumn(
            contentPadding = PaddingValues(Widgets.SCREEN_PADDING),
            verticalArrangement = Arrangement.spacedBy(ListGap),
        ) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    HomeScreen.Pending(state, settings, model)
                    Widgets.Header(stringResource(R.string.targets_mode))
                    Widgets.Segments(TargetMode.entries, settings.targetMode, { Labels.targetMode(it) }, model::setTargetMode)
                    Text(stringResource(R.string.targets_mode_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

                    Widgets.Header(stringResource(R.string.targets_extra))
                    Widgets.Group {
                        Widgets.Panel(0, 1) {
                            Widgets.StringList(
                                items = settings.extraPackages,
                                label = stringResource(R.string.settings_package),
                                validate = { PACKAGE.matches(it) },
                                onChange = { list -> model.configure { it.copy(extraPackages = list) } },
                            )
                        }
                    }
                    Text(stringResource(R.string.targets_extra_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

                    Widgets.Header(stringResource(R.string.targets_excluded))
                    Widgets.Group {
                        Widgets.Panel(0, 1) {
                            Widgets.StringList(
                                items = settings.excludedPackages,
                                label = stringResource(R.string.settings_package),
                                validate = { PACKAGE.matches(it) && it !in ALWAYS },
                                onChange = { list -> model.configure { it.copy(excludedPackages = list) } },
                            )
                        }
                    }
                    Text(stringResource(R.string.targets_excluded_help), style = MaterialTheme.typography.bodySmall, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))

                    Widgets.Header(pluralStringResource(R.plurals.targets_current, targets.size, targets.size))
                    if (state.status?.targets == null) {
                        Text(stringResource(R.string.targets_none), style = MaterialTheme.typography.bodyMedium, color = Widgets.secondary, modifier = Modifier.padding(horizontal = 16.dp))
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

    val ListGap = 2.dp

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
