package dev.nercone.replayintegrity.config

import dev.nercone.replayintegrity.engine.KeyRemoval
import dev.nercone.replayintegrity.engine.KeyRemovalSettings
import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.engine.TargetScope

/**
 * A set of choices for every setting that trades the safety of the user's data and of the
 * device against how surely and how quickly STRONG is reached. Choosing one sets them all; the
 * user can then change each one, and the settings no longer match any (`of` returns `null`).
 *
 * `BALANCED`, the default, is the safest set that still reaches STRONG almost surely: it never
 * removes a key that may hold what the user enrolled, and changes the keybox only when it must.
 * Each value equals the default of its setting (`Settings.Values` and the engine's `Settings`).
 */
enum class Protection(
    val keyboxReplacement: Settings.KeyboxReplacement,
    val targetScope: TargetScope,
    val targetMode: TargetMode,
    val playTargetMode: TargetMode,
    val keyRemoval: KeyRemovalSettings,
    val restartOnChange: Boolean,
    val endBackgroundApplications: Boolean,
) {
    /**
     * As little as possible is changed: only the Play stack and wallet applications are targets,
     * the keys of the Play stack stay in the device's keystore while it works (`AUTO`), no key
     * that may hold what the user enrolled is removed, and changes wait for the next reboot.
     * STRONG may be lost on a device whose own keystore fails attestation, and after a change
     * until the reboot.
     */
    SAFETY(
        keyboxReplacement = Settings.KeyboxReplacement.WHEN_NEEDED,
        targetScope = TargetScope.PLAY_AND_WALLETS,
        targetMode = TargetMode.AUTO,
        playTargetMode = TargetMode.AUTO,
        keyRemoval = KeyRemovalSettings(),
        restartOnChange = false,
        endBackgroundApplications = false,
    ),

    /** The defaults: see the documentation of the class. */
    BALANCED(
        keyboxReplacement = Settings.KeyboxReplacement.WHEN_NEEDED,
        targetScope = TargetScope.ALL_APPLICATIONS,
        targetMode = TargetMode.AUTO,
        playTargetMode = TargetMode.GENERATE,
        keyRemoval = KeyRemovalSettings(),
        restartOnChange = true,
        endBackgroundApplications = false,
    ),

    /**
     * Every outdated key is removed as soon as its keybox is replaced, and a mirror's newer
     * keybox is taken whenever it is not worse. Tap-and-pay cards, passkeys and applications'
     * enrolments are lost with their keys at every change of the keybox.
     */
    INTEGRITY(
        keyboxReplacement = Settings.KeyboxReplacement.NO_DOWNGRADE,
        targetScope = TargetScope.ALL_APPLICATIONS,
        targetMode = TargetMode.AUTO,
        playTargetMode = TargetMode.GENERATE,
        keyRemoval = KeyRemovalSettings(
            integrity = KeyRemoval.WHEN_REPLACED,
            play = KeyRemoval.WHEN_REPLACED,
            applications = KeyRemoval.WHEN_REPLACED,
            integrityPatch = true,
        ),
        restartOnChange = true,
        endBackgroundApplications = true,
    ),
    ;

    /** `values` with every setting of this set. */
    fun applyTo(values: Settings.Values): Settings.Values = values.copy(
        keyboxReplacement = keyboxReplacement,
        targetScope = targetScope,
        targetMode = targetMode,
        playTargetMode = playTargetMode,
        keyRemoval = keyRemoval,
        restartOnChange = restartOnChange,
        endBackgroundApplications = endBackgroundApplications,
    )

    companion object {
        val DEFAULT = BALANCED

        /** The set that `values` match, or `null` when the user adjusted them. */
        fun of(values: Settings.Values): Protection? = entries.firstOrNull { it.applyTo(values) == values }
    }
}
