package dev.nercone.replayintegrity.ui

import android.content.ActivityNotFoundException
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItemColors
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SegmentedListItem
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.res.colorResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.max
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.graphics.shapes.CornerRounding
import androidx.graphics.shapes.RoundedPolygon
import dev.nercone.replayintegrity.R

/** User interface parts shared by the screens. Each one is a complete part, with nothing specific to one screen. */
object Widgets {
    val SCREEN_PADDING = 16.dp
    val SPACING = 8.dp

    /** The width that text and lists stay readable at; wider windows centre the content. */
    val CONTENT_WIDTH = 720.dp

    /** The width from which a screen may lay its content out in two columns. */
    val TWO_COLUMNS = 840.dp

    /** The room a screen with a floating action button leaves under its last item. */
    val FLOATING_BUTTON_ROOM = 88.dp

    /** The tone of a notice. */
    enum class Tone { INFORMATION, WARNING, ERROR }

    /** How a state reads in the status card (`Hero`): as wanted, still unknown, or in need of the user. */
    enum class Mood { GOOD, NEUTRAL, BAD }

    /** The rounded hexagon of the application icon, for the emblem of the status card. */
    val HEXAGON: RoundedPolygon = RoundedPolygon(numVertices = 6, rounding = CornerRounding(0.22f)).normalized()

    /** An action of the status card. The first of the actions is the main one. */
    data class Action(val text: String, val icon: ImageVector, val enabled: Boolean, val onClick: () -> Unit)

    /**
     * A screen: a lazy list, centred at `maxWidth` in a wide window, that scrolls from anywhere in
     * the window. A screen that lays its items out in columns when there is room passes
     * `columnsWidth`, the width it is centred at instead when the window has room for
     * `TWO_COLUMNS`; `content` receives the width the list has, to decide. `spacing` is the gap
     * between items: a screen whose items form one segmented group (a long list) passes the gap of
     * such a group, and spaces its other items itself. `bottom` is the room under the last item
     * (more under a floating action button).
     */
    @Composable
    fun Screen(
        maxWidth: Dp = CONTENT_WIDTH,
        columnsWidth: Dp? = null,
        spacing: Dp = SPACING,
        bottom: Dp = SCREEN_PADDING * 2,
        content: LazyListScope.(width: Dp) -> Unit,
    ) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val room = this.maxWidth - SCREEN_PADDING * 2
            val widest = if (columnsWidth != null && room >= TWO_COLUMNS) columnsWidth else maxWidth
            val side = max(SCREEN_PADDING, (this.maxWidth - widest) / 2)
            val width = this.maxWidth - side * 2
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = side, end = side, top = SPACING, bottom = bottom),
                verticalArrangement = Arrangement.spacedBy(spacing),
            ) { content(width) }
        }
    }

    /** The title of a group of items. */
    @Composable
    fun Header(text: String, modifier: Modifier = Modifier) {
        Text(
            text,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp),
        )
    }

    /** An explanation under a group of items. */
    @Composable
    fun Help(text: String, color: Color = secondary) {
        Text(text, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.padding(horizontal = 16.dp))
    }

    /** A group of segmented list items: rounded as a whole, with a small gap between the items. */
    @Composable
    fun Group(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
        Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(ListItemDefaults.SegmentedGap), content = content)
    }

    /** A titled group with an optional explanation under it: the unit every screen is made of. */
    @Composable
    fun Section(title: String?, help: String? = null, content: @Composable ColumnScope.() -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(SPACING)) {
            title?.let { Header(it) }
            Group(content = content)
            help?.let { Help(it) }
        }
    }

    /** An item of a group. `index` and `count` decide which corners are rounded. */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Item(
        index: Int,
        count: Int,
        headline: String,
        supporting: String? = null,
        icon: ImageVector? = null,
        enabled: Boolean = true,
        trailing: (@Composable () -> Unit)? = null,
        colors: ListItemColors = ListItemDefaults.segmentedColors(),
        onClick: (() -> Unit)? = null,
    ) {
        val shapes = ListItemDefaults.segmentedShapes(index, count)
        val leading: (@Composable () -> Unit)? = icon?.let { { Icon(it, null) } }
        val support: (@Composable () -> Unit)? = supporting?.let { { Text(it) } }
        if (onClick != null) {
            SegmentedListItem(
                onClick = onClick,
                shapes = shapes,
                enabled = enabled,
                leadingContent = leading,
                trailingContent = trailing,
                supportingContent = support,
                colors = colors,
            ) { Text(headline) }
        } else {
            SegmentedListItem(shapes = shapes, enabled = enabled, leadingContent = leading, trailingContent = trailing, supportingContent = support, colors = colors) {
                Text(headline)
            }
        }
    }

    /** An item with a switch; the whole item toggles it. */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun SwitchItem(index: Int, count: Int, headline: String, supporting: String?, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
        SegmentedListItem(
            checked = checked,
            onCheckedChange = onChange,
            shapes = ListItemDefaults.segmentedShapes(index, count),
            enabled = enabled,
            supportingContent = supporting?.let { { Text(it) } },
            trailingContent = { Switch(checked = checked, onCheckedChange = null, enabled = enabled) },
        ) { Text(headline) }
    }

    /** An item with a radio button; the whole item selects it. */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun RadioItem(index: Int, count: Int, headline: String, supporting: String?, selected: Boolean, enabled: Boolean = true, onSelect: () -> Unit) {
        SegmentedListItem(
            selected = selected,
            onClick = onSelect,
            shapes = ListItemDefaults.segmentedShapes(index, count),
            enabled = enabled,
            leadingContent = { RadioButton(selected = selected, onClick = null, enabled = enabled) },
            supportingContent = supporting?.let { { Text(it) } },
        ) { Text(headline) }
    }

    /**
     * An item that shows the chosen one of `options` and opens a dialog to choose another. The
     * dialog lists every option with `help` under it, and `description` above them all.
     * `supporting` replaces the name of the chosen option under the headline.
     */
    @Composable
    fun <T> ChoiceItem(
        index: Int,
        count: Int,
        headline: String,
        options: List<T>,
        selected: T,
        describe: @Composable (T) -> String,
        onSelect: (T) -> Unit,
        icon: ImageVector? = null,
        supporting: String? = null,
        description: String? = null,
        help: (@Composable (T) -> String?)? = null,
        enabled: Boolean = true,
        trailing: (@Composable () -> Unit)? = null,
    ) {
        var open by rememberSaveable { mutableStateOf(false) }
        Item(index, count, headline, supporting ?: describe(selected), icon, enabled, trailing, onClick = { open = true })
        if (open) ChoiceDialog(headline, description, options, selected, describe, help, onSelect = { onSelect(it); open = false }, onDismiss = { open = false })
    }

    /** A dialog that picks one of `options`; choosing one closes it. */
    @Composable
    fun <T> ChoiceDialog(
        title: String,
        description: String?,
        options: List<T>,
        selected: T,
        describe: @Composable (T) -> String,
        help: (@Composable (T) -> String?)?,
        onSelect: (T) -> Unit,
        onDismiss: () -> Unit,
    ) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    description?.let { Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(bottom = 8.dp)) }
                    options.forEach { option ->
                        Row(
                            Modifier.fillMaxWidth()
                                .selectable(selected = option == selected, role = Role.RadioButton, onClick = { onSelect(option) })
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            RadioButton(selected = option == selected, onClick = null)
                            Column(Modifier.weight(1f)) {
                                Text(describe(option), style = MaterialTheme.typography.bodyLarge)
                                help?.invoke(option)?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = secondary) }
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
        )
    }

    /**
     * An item that shows a text setting of one word, such as a URL, and opens a dialog to edit
     * it. The text is trimmed as it is typed. `onSave` receives the text when it is valid and the
     * user confirms it.
     */
    @Composable
    fun TextItem(
        index: Int,
        count: Int,
        headline: String,
        value: String,
        validate: (String) -> Boolean,
        onSave: (String) -> Unit,
        icon: ImageVector? = null,
        keyboardType: KeyboardType = KeyboardType.Text,
    ) {
        var open by rememberSaveable { mutableStateOf(false) }
        Item(index, count, headline, value, icon, onClick = { open = true })
        if (open) {
            var text by rememberSaveable { mutableStateOf(value) }
            val valid = validate(text)
            AlertDialog(
                onDismissRequest = { open = false },
                title = { Text(headline) },
                text = {
                    OutlinedTextField(
                        text,
                        { text = it.trim() },
                        singleLine = true,
                        isError = !valid,
                        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
                        modifier = Modifier.fillMaxWidth(),
                    )
                },
                confirmButton = {
                    TextButton(enabled = valid, onClick = {
                        if (text != value) onSave(text)
                        open = false
                    }) { Text(stringResource(R.string.save)) }
                },
                dismissButton = { TextButton(onClick = { open = false }) { Text(stringResource(R.string.cancel)) } },
            )
        }
    }

    /** A message in a tinted container, with optional actions below it. */
    @Composable
    fun Notice(tone: Tone, title: String, text: String?, modifier: Modifier = Modifier, actions: (@Composable () -> Unit)? = null) {
        val (container, content, icon) = when (tone) {
            Tone.INFORMATION -> Triple(MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer, Icons.Default.Info)
            Tone.WARNING -> Triple(MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.colorScheme.onTertiaryContainer, Icons.Default.WarningAmber)
            Tone.ERROR -> Triple(MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer, Icons.Default.ErrorOutline)
        }
        Surface(modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large, color = container, contentColor = content) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(icon, null)
                    Text(title, style = MaterialTheme.typography.titleMedium)
                }
                text?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
                actions?.let { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End)) { it() } }
            }
        }
    }

    /**
     * The status card at the top of the home screen: an emblem, the state in a title and a
     * sentence, an optional `detail` (such as the error of a reading) and the actions. While
     * `busy`, the emblem is a loading indicator. `emblem` draws on the hexagon in the color it is
     * given; the hexagon turns when the state becomes good, and back when it no longer is.
     */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Hero(
        mood: Mood,
        busy: Boolean,
        title: String,
        text: String,
        detail: String? = null,
        actions: List<Action> = emptyList(),
        help: String? = null,
        emblem: @Composable (Color) -> Unit,
    ) {
        val colors = MaterialTheme.colorScheme
        val effects = MaterialTheme.motionScheme.defaultEffectsSpec<Color>()
        val container by animateColorAsState(
            when (mood) {
                Mood.GOOD -> colors.primaryContainer
                Mood.NEUTRAL -> colors.surface
                Mood.BAD -> colors.errorContainer
            },
            effects,
            label = "container",
        )
        val shape by animateColorAsState(
            when (mood) {
                Mood.GOOD -> colors.primary
                Mood.NEUTRAL -> colors.outline
                Mood.BAD -> colors.error
            },
            effects,
            label = "emblem",
        )
        val onShape = when (mood) {
            Mood.GOOD -> colors.onPrimary
            Mood.NEUTRAL -> colors.surface
            Mood.BAD -> colors.onError
        }
        // A hexagon turned by 60 degrees is the same hexagon: the turn is seen only while it runs.
        val rotation by animateFloatAsState(if (mood == Mood.GOOD) 60f else 0f, MaterialTheme.motionScheme.slowSpatialSpec(), label = "rotation")
        Surface(Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.extraLarge, color = container) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Box(Modifier.size(EMBLEM_SIZE), contentAlignment = Alignment.Center) {
                        if (busy) {
                            ContainedLoadingIndicator(Modifier.size(EMBLEM_SIZE))
                        } else {
                            Box(Modifier.size(EMBLEM_SIZE).rotate(rotation).clip(HEXAGON.toShape()).background(shape))
                            emblem(onShape)
                        }
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(title, style = MaterialTheme.typography.headlineSmall)
                        Text(text, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                detail?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                if (actions.isNotEmpty()) Actions(actions)
                help?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
    }

    /** The size of the emblem of the status card. */
    val EMBLEM_SIZE = 72.dp

    /** A row of buttons of equal width: the first is the main action, the others are tonal. */
    @OptIn(ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Actions(actions: List<Action>, modifier: Modifier = Modifier) {
        val height = ButtonDefaults.MediumContainerHeight
        Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(SPACING)) {
            actions.forEachIndexed { index, action ->
                val content: @Composable RowScope.() -> Unit = {
                    Icon(action.icon, null, Modifier.size(ButtonDefaults.iconSizeFor(height)))
                    Spacer(Modifier.size(ButtonDefaults.iconSpacingFor(height)))
                    Text(action.text, style = ButtonDefaults.textStyleFor(height), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                val button = Modifier.weight(1f).heightIn(min = height)
                val padding = ButtonDefaults.contentPaddingFor(height)
                if (index == 0) {
                    Button(onClick = action.onClick, enabled = action.enabled, shapes = ButtonDefaults.shapes(), contentPadding = padding, modifier = button, content = content)
                } else {
                    FilledTonalButton(onClick = action.onClick, enabled = action.enabled, shapes = ButtonDefaults.shapes(), contentPadding = padding, modifier = button, content = content)
                }
            }
        }
    }

    /**
     * The name of the application with its icon and `text` under it (such as the version), for
     * the page about the application. The icon is drawn from the parts of the adaptive icon,
     * which a painter cannot draw whole.
     */
    @Composable
    fun Identity(text: String) {
        Panel(0, 1) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Box(Modifier.size(64.dp).clip(MaterialTheme.shapes.large).background(colorResource(R.color.ic_launcher_background))) {
                    Image(painterResource(R.drawable.ic_launcher_foreground), null, Modifier.fillMaxSize())
                }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge)
                    Text(text, style = MaterialTheme.typography.bodyMedium, color = secondary)
                }
            }
        }
    }

    /** A dialog that asks to confirm a destructive or far-reaching action. */
    @Composable
    fun Confirm(title: String, text: String, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = { Text(text) },
            confirmButton = {
                TextButton(onClick = {
                    onConfirm()
                    onDismiss()
                }) { Text(confirm) }
            },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
        )
    }

    /** A line of a label and a value, for details. */
    @Composable
    fun Field(label: String, value: String, monospace: Boolean = false) {
        Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = secondary)
            Text(
                value,
                style = if (monospace) MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium,
            )
        }
    }

    /** A surface for content that is not a list item, matching the items of a group. */
    @Composable
    fun Panel(index: Int, count: Int, color: Color = MaterialTheme.colorScheme.surface, onClick: (() -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
        val shape = when {
            count == 1 -> MaterialTheme.shapes.large
            index == 0 -> MaterialTheme.shapes.large.copy(bottomStart = MaterialTheme.shapes.extraSmall.bottomStart, bottomEnd = MaterialTheme.shapes.extraSmall.bottomEnd)
            index == count - 1 -> MaterialTheme.shapes.large.copy(topStart = MaterialTheme.shapes.extraSmall.topStart, topEnd = MaterialTheme.shapes.extraSmall.topEnd)
            else -> MaterialTheme.shapes.extraSmall
        }
        Surface(shape = shape, color = color, modifier = Modifier.fillMaxWidth()) {
            Column(
                (if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                content = content,
            )
        }
    }

    /**
     * An editable list of strings, such as package names. `validate` decides which text can be
     * added. Each change is told as the one string added or removed, not as a whole new list:
     * the list shown may be older than the stored one while a change is being saved, and a list
     * built from it would undo that change.
     */
    @Composable
    fun StringList(items: List<String>, label: String, validate: (String) -> Boolean, onAdd: (String) -> Unit, onRemove: (String) -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items.forEach { item ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(item, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    IconButton(onClick = { onRemove(item) }) { Icon(Icons.Default.Close, stringResource(R.string.remove)) }
                }
            }
            var text by rememberSaveable { mutableStateOf("") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(text, { text = it.trim() }, label = { Text(label) }, singleLine = true, modifier = Modifier.weight(1f))
                IconButton(enabled = validate(text) && text !in items, onClick = {
                    onAdd(text)
                    text = ""
                }) { Icon(Icons.Default.Add, stringResource(R.string.add)) }
            }
        }
    }

    /** An item that shows a list of strings and opens a dialog to edit it (`StringList`). */
    @Composable
    fun StringListItem(
        index: Int,
        count: Int,
        headline: String,
        items: List<String>,
        label: String,
        help: String,
        validate: (String) -> Boolean,
        onAdd: (String) -> Unit,
        onRemove: (String) -> Unit,
        icon: ImageVector? = null,
    ) {
        var open by rememberSaveable { mutableStateOf(false) }
        Item(index, count, headline, if (items.isEmpty()) stringResource(R.string.none) else items.joinToString(", "), icon, onClick = { open = true })
        if (open) {
            AlertDialog(
                onDismissRequest = { open = false },
                title = { Text(headline) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(help, style = MaterialTheme.typography.bodyMedium)
                        StringList(items, label, validate, onAdd, onRemove)
                    }
                },
                confirmButton = { TextButton(onClick = { open = false }) { Text(stringResource(R.string.done)) } },
            )
        }
    }

    /** A dropdown to pick one of `options`, shown with `label`. */
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun <T> Dropdown(label: String, options: List<T>, selected: T?, describe: (T) -> String, onSelect: (T) -> Unit, modifier: Modifier = Modifier) {
        var expanded by remember { mutableStateOf(false) }
        ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }, modifier = modifier) {
            OutlinedTextField(
                value = selected?.let(describe).orEmpty(),
                onValueChange = {},
                readOnly = true,
                singleLine = true,
                label = { Text(label) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { option ->
                    DropdownMenuItem(text = { Text(describe(option)) }, onClick = {
                        onSelect(option)
                        expanded = false
                    })
                }
            }
        }
    }

    /** A row of segmented buttons to pick one of a few `options` with short names. */
    @Composable
    fun <T> Segments(options: List<T>, selected: T, describe: @Composable (T) -> String, onSelect: (T) -> Unit, modifier: Modifier = Modifier) {
        SingleChoiceSegmentedButtonRow(modifier.fillMaxWidth()) {
            options.forEachIndexed { index, option ->
                SegmentedButton(
                    selected = option == selected,
                    onClick = { onSelect(option) },
                    shape = SegmentedButtonDefaults.itemShape(index, options.size),
                ) { Text(describe(option)) }
            }
        }
    }

    /** A full-screen editor with a close button and a save action, its content centred at a readable width. */
    @OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
    @Composable
    fun Editor(title: String, canSave: Boolean, onSave: () -> Unit, onDismiss: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
        Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)) {
            Scaffold(
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                topBar = {
                    TopAppBar(
                        title = { Text(title) },
                        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
                        navigationIcon = { IconButton(onClick = onDismiss) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.cancel)) } },
                        actions = {
                            Button(
                                onClick = onSave,
                                enabled = canSave,
                                shapes = ButtonDefaults.shapes(),
                                modifier = Modifier.padding(end = 8.dp),
                            ) { Text(stringResource(R.string.save)) }
                        },
                    )
                },
            ) { padding ->
                BoxWithConstraints(Modifier.fillMaxSize().padding(padding)) {
                    val side = max(SCREEN_PADDING, (maxWidth - CONTENT_WIDTH) / 2)
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = side, vertical = SCREEN_PADDING),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        content = content,
                    )
                }
            }
        }
    }

    /**
     * Opens `uri` in the application that handles it, when the user asked for it. A system
     * without such an application (a browser) has none to open it with, which is not an error.
     */
    fun open(handler: UriHandler, uri: String) {
        try {
            handler.openUri(uri)
        } catch (error: IllegalArgumentException) {
            // No activity handles the link.
        } catch (error: ActivityNotFoundException) {
            // No activity handles the link.
        }
    }

    /** The color of secondary text. */
    val secondary: Color @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
}
