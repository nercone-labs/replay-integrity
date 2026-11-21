package dev.nercone.replayintegrity.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.engine.ApplyReport

/**
 * What every screen tells at its top, the same way on each: the outcome of the last operation,
 * and the settings that changed since they were applied. A restricted root is told by a dialog
 * of the frame instead (`Frame.Restricted`).
 */
object Notices {
    /**
     * Adds the notices to the list of a screen, before its own items. `extra` is added under
     * each, for a screen whose list spaces its items less than `Widgets.SPACING`.
     */
    fun LazyListScope.notices(data: ScreenData, model: AppViewModel, extra: Dp = 0.dp) {
        val outcome = data.state.outcome?.takeIf { (it as? Outcome.Failed)?.restricted != true }
        if (outcome != null) item(key = "outcome") {
            Box(Modifier.padding(bottom = extra)) { Outcome(outcome, onLog = { model.showLog(true) }, onDismiss = model::dismissOutcome) }
        }
        if (data.pending) item(key = "pending") { Box(Modifier.padding(bottom = extra)) { Pending(data.state.idle, onApply = model::repair) } }
    }

    @Composable
    fun Pending(idle: Boolean, onApply: () -> Unit) {
        Widgets.Notice(Widgets.Tone.INFORMATION, stringResource(R.string.pending_title), stringResource(R.string.pending_text)) {
            FilledTonalButton(onClick = onApply, enabled = idle) { Text(stringResource(R.string.apply_now)) }
        }
    }

    @Composable
    fun Outcome(outcome: Outcome, onLog: () -> Unit, onDismiss: () -> Unit) {
        val (tone, title, text) = describe(outcome)
        Widgets.Notice(tone, title, text) {
            TextButton(onClick = onLog) { Text(stringResource(R.string.show_log)) }
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.dismiss)) }
        }
    }

    /** The tone, the title and the text of `outcome`. */
    @Composable
    fun describe(outcome: Outcome): Triple<Widgets.Tone, String, String?> = when (outcome) {
        is Outcome.Refreshed -> {
            val refreshed = outcome.refreshed
            val lines = buildList {
                refreshed.keybox?.let { add(stringResource(if (it.changed) R.string.outcome_keybox_new else R.string.outcome_keybox_same)) }
                refreshed.fingerprint?.let { add(stringResource(if (it.changed) R.string.outcome_fingerprint_new else R.string.outcome_fingerprint_same)) }
                add(applySummary(refreshed.apply, refreshed.apply.daemonRestarted))
                addAll(refreshed.problems)
            }
            val clean = refreshed.problems.isEmpty()
            Triple(
                if (clean) Widgets.Tone.INFORMATION else Widgets.Tone.WARNING,
                stringResource(if (clean) R.string.outcome_refreshed else R.string.outcome_refreshed_problems),
                lines.joinToString("\n"),
            )
        }
        is Outcome.Repaired -> Triple(Widgets.Tone.INFORMATION, stringResource(R.string.outcome_repaired), applySummary(outcome.repaired.apply, outcome.repaired.restarted))
        is Outcome.Installed -> Triple(
            Widgets.Tone.INFORMATION,
            stringResource(R.string.outcome_installed),
            stringResource(R.string.outcome_installed_text) + "\n" + applySummary(outcome.repaired.apply, outcome.repaired.restarted),
        )
        is Outcome.Restarted -> Triple(
            if (outcome.restarted) Widgets.Tone.INFORMATION else Widgets.Tone.WARNING,
            stringResource(R.string.outcome_restarted),
            stringResource(if (outcome.restarted) R.string.outcome_restarted_text else R.string.outcome_not_restarted_text),
        )
        is Outcome.ModuleInstalled -> Triple(Widgets.Tone.INFORMATION, stringResource(R.string.outcome_module), stringResource(R.string.outcome_module_text))
        is Outcome.ConflictsDisabled -> Triple(
            Widgets.Tone.INFORMATION,
            stringResource(R.string.outcome_conflicts_disabled),
            (outcome.modules.map { stringResource(R.string.conflict_disabled_module, it.name ?: it.id, it.id) } + stringResource(R.string.outcome_conflicts_disabled_text)).joinToString("\n"),
        )
        is Outcome.KeyRemoved -> Triple(
            if (outcome.report.kept == 0) Widgets.Tone.INFORMATION else Widgets.Tone.WARNING,
            stringResource(R.string.outcome_key_removed),
            stringResource(if (outcome.report.kept == 0) R.string.outcome_key_removed_text else R.string.outcome_key_kept_text),
        )
        is Outcome.Failed -> Triple(Widgets.Tone.ERROR, stringResource(R.string.outcome_failed), outcome.text)
    }

    @Composable
    fun applySummary(report: ApplyReport, restarted: Boolean): String = listOfNotNull(
        pluralStringResource(R.plurals.summary_targets, report.targets, report.targets),
        pluralStringResource(R.plurals.summary_stale_removed, report.staleKeysRemoved, report.staleKeysRemoved),
        report.staleKeysKept.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.summary_stale_kept, it, it) },
        report.outdatedKeysKept.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.summary_outdated_kept, it, it) },
        stringResource(R.string.summary_keybox_repaired).takeIf { report.keyboxRepaired },
        stringResource(if (restarted) R.string.summary_restarted else R.string.summary_not_restarted),
    ).joinToString("\n")
}
