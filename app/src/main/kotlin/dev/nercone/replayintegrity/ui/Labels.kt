package dev.nercone.replayintegrity.ui

import android.text.format.DateUtils
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.Problem
import dev.nercone.replayintegrity.engine.RootManager
import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeStatus
import java.text.DateFormat
import java.util.Date

/** The words the screens use for the values of the engine and the privileges. */
object Labels {
    @Composable
    fun privilege(kind: Privilege.Kind): String = stringResource(
        when (kind) {
            Privilege.Kind.ROOT -> R.string.privilege_root
            Privilege.Kind.SHIZUKU -> R.string.privilege_shizuku
            Privilege.Kind.SUI -> R.string.privilege_sui
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

    @Composable
    fun rootManager(manager: RootManager): String = stringResource(
        when (manager) {
            RootManager.MAGISK -> R.string.manager_magisk
            RootManager.KERNEL_SU -> R.string.manager_kernelsu
            RootManager.APATCH -> R.string.manager_apatch
        },
    )

    @Composable
    fun rootManagers(managers: List<RootManager>): String = managers.map { rootManager(it) }.joinToString(" / ")

    @Composable
    fun component(component: Component): String = stringResource(if (component == Component.KEYSTORE) R.string.component_keystore else R.string.component_integrity)

    /** The module that provides `component`. */
    fun moduleName(component: Component): String = if (component == Component.KEYSTORE) "TEESimulator-RS" else "Play Integrity Fork"

    /** The releases page of the module that provides `component`. */
    fun moduleReleases(component: Component): String =
        if (component == Component.KEYSTORE) "https://github.com/Enginex0/TEESimulator-RS/releases" else "https://github.com/osm0sis/PlayIntegrityFork/releases"

    @Composable
    fun targetMode(mode: TargetMode): String = stringResource(
        when (mode) {
            TargetMode.AUTO -> R.string.target_mode_auto
            TargetMode.GENERATE -> R.string.target_mode_generate
            TargetMode.PATCH -> R.string.target_mode_patch
        },
    )

    @Composable
    fun spoofFlag(key: String): String = when (key) {
        "spoofBuild" -> stringResource(R.string.spoof_build)
        "spoofProps" -> stringResource(R.string.spoof_props)
        "spoofProvider" -> stringResource(R.string.spoof_provider)
        "spoofSignature" -> stringResource(R.string.spoof_signature)
        "spoofVendingFinger" -> stringResource(R.string.spoof_vending_finger)
        "spoofVendingSdk" -> stringResource(R.string.spoof_vending_sdk)
        else -> key
    }

    /** A problem of a key or a fingerprint, in words. */
    @Composable
    fun problem(problem: Problem): String = when (problem.name) {
        "keyMismatch" -> stringResource(R.string.problem_key_mismatch)
        "malformedAttestation" -> stringResource(R.string.problem_malformed_attestation)
        "notHardwareBacked" -> stringResource(R.string.problem_not_hardware)
        "empty" -> stringResource(R.string.problem_empty_chain)
        "brokenLink" -> stringResource(R.string.problem_broken_link)
        "notSelfIssued" -> stringResource(R.string.problem_not_self_issued)
        "untrustedRoot" -> stringResource(R.string.problem_untrusted_root)
        "notYetValid" -> stringResource(R.string.problem_not_yet_valid)
        "expired" -> problem.number("not_after")?.let { stringResource(R.string.problem_expired_on, date(it)) }
            ?: problem.number("expires")?.let { stringResource(R.string.problem_expired_on, date(it)) }
            ?: stringResource(R.string.problem_expired)
        "revoked" -> stringResource(R.string.problem_revoked, problem.text("reason") ?: problem.text("status").orEmpty())
        "missing" -> stringResource(R.string.problem_missing, problem.text("key").orEmpty())
        "invalidFingerprint" -> stringResource(R.string.problem_invalid_fingerprint)
        "inconsistent" -> stringResource(R.string.problem_inconsistent, problem.text("key").orEmpty())
        "notRelease" -> stringResource(R.string.problem_not_release)
        "invalidPatch" -> stringResource(R.string.problem_invalid_patch)
        else -> problem.name
    }

    /** A time in seconds since the Unix epoch, as a local date. */
    fun date(seconds: Long): String = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(seconds * 1000))

    /** A time in seconds since the Unix epoch, as a local date and time. */
    fun dateTime(seconds: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))

    /** A time in milliseconds since the Unix epoch, relative to now ("5 minutes ago"). */
    fun relative(millis: Long): String =
        DateUtils.getRelativeTimeSpanString(millis, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS, DateUtils.FORMAT_ABBREV_RELATIVE).toString()

    /** The first characters of a hash, enough to tell files apart. */
    fun shortHash(sha256: String): String = sha256.take(12)
}
