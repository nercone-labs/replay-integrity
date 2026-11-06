package dev.nercone.replayintegrity.config

import android.content.Context
import androidx.core.content.edit
import dev.nercone.replayintegrity.engine.EngineSettings
import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The preferences of the application, kept as one immutable value and stored as one JSON
 * document, so that a change is written whole or not at all.
 */
class Settings(context: Context) {
    val preferences = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
    val values = MutableStateFlow(read())

    /** The preferences. Every field has a default, so that a document of an earlier version reads. */
    @Serializable
    data class Values(
        /** Which privilege runs the engine. */
        val privilege: PrivilegeChoice = PrivilegeChoice.AUTOMATIC,
        /**
         * Whether the user declined a permission the application asked for on its own. It is then
         * asked for only when the user chooses to grant it, until the privilege choice changes.
         */
        val permissionDeclined: Boolean = false,
        /** Whether the keybox is downloaded and replaced on every refresh. */
        val autoKeybox: Boolean = true,
        /** Whether the fingerprint is downloaded and replaced on every refresh. */
        val autoFingerprint: Boolean = true,
        /** Where the keybox is downloaded from (base64 of the keybox XML). */
        val keyboxUrl: String = Downloader.DEFAULT_KEYBOX_URL,
        /** Where the fingerprint is downloaded from (a `custom.pif.prop`). */
        val fingerprintUrl: String = Downloader.DEFAULT_FINGERPRINT_URL,
        /** Hours between scheduled refreshes; 0 turns them off. */
        val refreshHours: Int = DEFAULT_REFRESH_HOURS,
        /** Whether scheduled refreshes wait for an unmetered network. */
        val refreshUnmetered: Boolean = false,
        /**
         * Whether a change restarts the keystore daemon and ends the Play processes, so that it
         * takes effect at once. Otherwise it takes effect at the next reboot.
         */
        val restartOnChange: Boolean = true,
        /** Whether the root manager runs the engine at every boot, before the framework starts. */
        val bootHook: Boolean = true,
        /** Whether the application repairs after every boot, once the system has started. */
        val repairAfterBoot: Boolean = true,
        /** Whether a failure of a scheduled or boot run is notified. */
        val notifyFailures: Boolean = true,
        /** Whether the notification permission was asked for on its own, which happens once. */
        val notificationsAsked: Boolean = false,
        /** Whether the configuration has been applied at least once. */
        val applied: Boolean = false,
        /** Packages added to the attestation targets. */
        val extraPackages: List<String> = emptyList(),
        /** Installed packages left out of the attestation targets. */
        val excludedPackages: List<String> = emptyList(),
        /** How TEESimulator-RS handles the keys of every target. */
        val targetMode: TargetMode = TargetMode.AUTO,
        /** Overrides of the spoof flags, by key; a flag without one has its recommended value. */
        val spoofOverrides: Map<String, Boolean> = emptyMap(),
        /** When the last refresh finished, in milliseconds since the Unix epoch. */
        val lastRefreshAt: Long? = null,
        /** The problems of the last refresh; empty when it succeeded. */
        val lastRefreshProblems: List<String> = emptyList(),
    ) {
        /** The part of the settings that the engine reads. */
        fun engine(): EngineSettings = EngineSettings(
            extraPackages = extraPackages,
            excludedPackages = excludedPackages,
            targetMode = targetMode,
            spoofOverrides = spoofOverrides.map { (key, value) -> EngineSettings.override(key, value) },
        )
    }

    fun read(): Values {
        val text = preferences.getString(VALUES, null) ?: return Values()
        return runCatching { JSON.decodeFromString(Values.serializer(), text) }.getOrDefault(Values())
    }

    /** Replaces the settings with `transform` of the current ones, and stores them. */
    @Synchronized
    fun update(transform: (Values) -> Values) {
        val next = transform(values.value)
        preferences.edit(commit = true) { putString(VALUES, JSON.encodeToString(Values.serializer(), next)) }
        values.value = next
    }

    companion object {
        const val NAME = "settings"
        const val VALUES = "values"
        const val DEFAULT_REFRESH_HOURS = 6
        val REFRESH_CHOICES = listOf(0, 3, 6, 12, 24)
        val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true; coerceInputValues = true }
    }
}
