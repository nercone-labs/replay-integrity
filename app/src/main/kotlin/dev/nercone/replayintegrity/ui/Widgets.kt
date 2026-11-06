package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItemColors
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SegmentedListItem
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R

/** User interface parts shared by the screens. */
object Widgets {
    val SCREEN_PADDING = 16.dp
    val SPACING = 16.dp

    /** The tone of a notice. */
    enum class Tone { INFORMATION, WARNING, ERROR }

    /** The title of a group of items. */
    @Composable
    fun Header(text: String, modifier: Modifier = Modifier) {
        Text(
            text,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = modifier.padding(start = 16.dp, top = 8.dp, bottom = 4.dp),
        )
    }

    /** A group of segmented list items: rounded as a whole, with a small gap between the items. */
    @Composable
    fun Group(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
        Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(ListItemDefaults.SegmentedGap), content = content)
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
    fun RadioItem(index: Int, count: Int, headline: String, supporting: String?, selected: Boolean, onSelect: () -> Unit) {
        SegmentedListItem(
            selected = selected,
            onClick = onSelect,
            shapes = ListItemDefaults.segmentedShapes(index, count),
            leadingContent = { RadioButton(selected = selected, onClick = null) },
            supportingContent = supporting?.let { { Text(it) } },
        ) { Text(headline) }
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

    /** A row of segmented buttons to pick one of `options`. */
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

    /**
     * A text setting: the field keeps what the user types, and `onSave` receives it when it is
     * valid and the user confirms it.
     */
    @Composable
    fun TextSetting(value: String, label: String, validate: (String) -> Boolean, onSave: (String) -> Unit, modifier: Modifier = Modifier) {
        var text by remember(value) { mutableStateOf(value) }
        val valid = validate(text)
        Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                text,
                { text = it.trim() },
                label = { Text(label) },
                singleLine = true,
                isError = !valid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.weight(1f),
            )
            IconButton(enabled = valid && text != value, onClick = { onSave(text) }) { Icon(Icons.Default.Check, stringResource(R.string.save)) }
        }
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
    fun Panel(index: Int, count: Int, content: @Composable ColumnScope.() -> Unit) {
        val shape = when {
            count == 1 -> MaterialTheme.shapes.large
            index == 0 -> MaterialTheme.shapes.large.copy(bottomStart = MaterialTheme.shapes.extraSmall.bottomStart, bottomEnd = MaterialTheme.shapes.extraSmall.bottomEnd)
            index == count - 1 -> MaterialTheme.shapes.large.copy(topStart = MaterialTheme.shapes.extraSmall.topStart, topEnd = MaterialTheme.shapes.extraSmall.topEnd)
            else -> MaterialTheme.shapes.extraSmall
        }
        Surface(shape = shape, color = MaterialTheme.colorScheme.surface, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
        }
    }

    /** An editable list of strings, such as packages or components. */
    @Composable
    fun StringList(items: List<String>, label: String, validate: (String) -> Boolean, onChange: (List<String>) -> Unit) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items.forEach { item ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(item, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    IconButton(onClick = { onChange(items - item) }) { Icon(Icons.Default.Close, stringResource(R.string.remove)) }
                }
            }
            var text by remember { mutableStateOf("") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(text, { text = it.trim() }, label = { Text(label) }, singleLine = true, modifier = Modifier.weight(1f))
                IconButton(enabled = validate(text) && text !in items, onClick = {
                    onChange(items + text)
                    text = ""
                }) { Icon(Icons.Default.Add, stringResource(R.string.add)) }
            }
        }
    }

    /** The color of secondary text. */
    val secondary: Color @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant
}
