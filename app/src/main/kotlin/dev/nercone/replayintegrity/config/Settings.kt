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
import kotlinx.serialization.json.jsonObject

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
        /** Where the keybox is downloaded from (the keybox XML, or base64 of it). */
        val keyboxUrl: String = Downloader.DEFAULT_KEYBOX_URL,
        /**
         * More keybox sources, tried in order after `keyboxUrl` when it cannot be downloaded or
         * serves a keybox that ranks below the installed one.
         */
        val extraKeyboxUrls: List<String> = emptyList(),
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
        /**
         * Whether the boot hook also runs the package watcher, which rebuilds the target list as
         * soon as an application is installed or removed, instead of at the next refresh.
         */
        val watchPackages: Boolean = true,
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
        /** How TEESimulator-RS handles the keys of every target but the Play stack. */
        val targetMode: TargetMode = TargetMode.AUTO,
        /** How TEESimulator-RS handles the keys of the Play stack; generating them is recommended. */
        val playTargetMode: TargetMode = TargetMode.GENERATE,
        /** Overrides of the spoof flags, by key; a flag without one has its recommended value. */
        val spoofOverrides: Map<String, Boolean> = emptyMap(),
        /** When the last refresh finished, in milliseconds since the Unix epoch. */
        val lastRefreshAt: Long? = null,
        /** The problems of the last refresh; empty when it succeeded. */
        val lastRefreshProblems: List<String> = emptyList(),
    ) {
        /** The keybox sources in the order they are tried: `keyboxUrl`, then `extraKeyboxUrls`. */
        fun keyboxSources(): List<String> = (listOf(keyboxUrl) + extraKeyboxUrls).distinct()

        /** The part of the settings that the engine reads. */
        fun engine(): EngineSettings = EngineSettings(
            extraPackages = extraPackages,
            excludedPackages = excludedPackages,
            targetMode = targetMode,
            playTargetMode = playTargetMode,
            spoofOverrides = spoofOverrides.map { (key, value) -> EngineSettings.override(key, value) },
        )
    }

    fun read(): Values {
        val text = preferences.getString(VALUES, null) ?: return Values()
        return runCatching { decode(text) }.getOrDefault(Values())
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

        /**
         * Decodes a stored document. A document written before `playTargetMode` existed gave the
         * Play stack `targetMode`; a mode other than automatic was the user's choice, so the Play
         * stack keeps it, as the engine's `Settings::parse` does.
         */
        fun decode(text: String): Values {
            val values = JSON.decodeFromString(Values.serializer(), text)
            val stored = JSON.parseToJsonElement(text).jsonObject
            return if ("playTargetMode" !in stored && values.targetMode != TargetMode.AUTO) values.copy(playTargetMode = values.targetMode) else values
        }
    }
}
