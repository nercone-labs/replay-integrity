package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** Small building blocks shared by the screens. */
object Widgets {
    val SCREEN_PADDING = 16.dp

    val secondary: Color
        @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant

    /** A titled card holding rows. */
    @Composable
    fun Section(title: String, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
        Column(modifier) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = secondary,
                modifier = Modifier.padding(start = 12.dp, bottom = 6.dp),
            )
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)) {
                Column(Modifier.padding(vertical = 4.dp), content = content)
            }
        }
    }

    /** A row with a leading status icon, a title and optional supporting text. */
    @Composable
    fun StatusRow(icon: ImageVector, tint: Color, title: String, supporting: String? = null) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(24.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                if (supporting != null) {
                    Text(supporting, style = MaterialTheme.typography.bodyMedium, color = secondary)
                }
            }
        }
    }

    /** A row with a title, supporting text and a trailing switch. */
    @Composable
    fun SwitchRow(title: String, supporting: String?, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                if (supporting != null) {
                    Text(supporting, style = MaterialTheme.typography.bodyMedium, color = secondary, overflow = TextOverflow.Visible)
                }
            }
            Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
        }
    }
}
