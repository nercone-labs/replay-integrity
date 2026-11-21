package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedListItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.max
import dev.nercone.replayintegrity.R

/** User interface parts shared by the screens. Each one is a complete part, with nothing specific to one screen. */
object Widgets {
    val SCREEN_PADDING = 16.dp
    val SPACING = 8.dp

    /** The width that text and lists stay readable at; wider windows centre the content. */
    val CONTENT_WIDTH = 720.dp

    /** The tone of a notice. */
    enum class Tone { INFORMATION, WARNING, ERROR }

    /**
     * A screen: a lazy list, centred at `maxWidth` in a wide window, that scrolls from anywhere in
     * the window. `content` receives the width the list has, so that a screen can lay its items
     * out in columns when there is room. `spacing` is the gap between items: a screen whose
     * items form one segmented group (a long list) passes the gap of such a group, and spaces its
     * other items itself.
     */
    @Composable
    fun Screen(maxWidth: Dp = CONTENT_WIDTH, spacing: Dp = SPACING, content: LazyListScope.(width: Dp) -> Unit) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val side = max(SCREEN_PADDING, (this.maxWidth - maxWidth) / 2)
            val width = this.maxWidth - side * 2
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = side, end = side, top = SPACING, bottom = SCREEN_PADDING * 2),
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
        onClick: (() -> Unit)? = null,
    ) {
        val shapes = ListItemDefaults.segmentedShapes(index, count)
        val leading: (@Composable () -> Unit)? = icon?.let { { Icon(it, null) } }
        val support: (@Composable () -> Unit)? = supporting?.let { { Text(it) } }
        val colors = ListItemDefaults.segmentedColors()
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
     * An item that shows a text setting and opens a dialog to edit it. `onSave` receives the
     * text when it is valid and the user confirms it.
     */
    @Composable
    fun TextItem(index: Int, count: Int, headline: String, value: String, validate: (String) -> Boolean, onSave: (String) -> Unit, icon: ImageVector? = null) {
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
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
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
    fun Panel(index: Int, count: Int, onClick: (() -> Unit)? = null, content: @Composable ColumnScope.() -> Unit) {
        val shape = when {
            count == 1 -> MaterialTheme.shapes.large
            index == 0 -> MaterialTheme.shapes.large.copy(bottomStart = MaterialTheme.shapes.extraSmall.bottomStart, bottomEnd = MaterialTheme.shapes.extraSmall.bottomEnd)
            index == count - 1 -> MaterialTheme.shapes.large.copy(topStart = MaterialTheme.shapes.extraSmall.topStart, topEnd = MaterialTheme.shapes.extraSmall.topEnd)
            else -> MaterialTheme.shapes.extraSmall
        }
        Surface(shape = shape, color = MaterialTheme.colorScheme.surface, modifier = Modifier.fillMaxWidth()) {
            Column(
                (if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                content = content,
            )
        }
    }

    /** An editable list of strings, such as package names. `validate` decides which text can be added. */
    @Composable
    fun StringList(items: List<String>, label: String, validate: (String) -> Boolean, onChange: (List<String>) -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items.forEach { item ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(item, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    IconButton(onClick = { onChange(items - item) }) { Icon(Icons.Default.Close, stringResource(R.string.remove)) }
                }
            }
            var text by rememberSaveable { mutableStateOf("") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(text, { text = it.trim() }, label = { Text(label) }, singleLine = true, modifier = Modifier.weight(1f))
                IconButton(enabled = validate(text) && text !in items, onClick = {
                    onChange(items + text)
                    text = ""
                }) { Icon(Icons.Default.Add, stringResource(R.string.add)) }
            }
        }
    }

    /** An item that shows a list of strings by count and opens a dialog to edit it (`StringList`). */
    @Composable
    fun StringListItem(index: Int, count: Int, headline: String, items: List<String>, label: String, help: String, validate: (String) -> Boolean, onChange: (List<String>) -> Unit, icon: ImageVector? = null) {
        var open by rememberSaveable { mutableStateOf(false) }
        Item(index, count, headline, if (items.isEmpty()) stringResource(R.string.none) else items.joinToString(", "), icon, onClick = { open = true })
        if (open) {
            AlertDialog(
                onDismissRequest = { open = false },
                title = { Text(headline) },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(help, style = MaterialTheme.typography.bodyMedium)
                        StringList(items, label, validate, onChange)
                    }
                },
                confirmButton = { TextButton(onClick = { open = false }) { Text(stringResource(R.string.done)) } },
            )
        }
    }

    /** The color of secondary text. */
    val secondary: Color @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
}
