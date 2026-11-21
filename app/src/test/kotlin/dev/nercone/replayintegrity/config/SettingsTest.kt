package dev.nercone.replayintegrity.config

import dev.nercone.replayintegrity.engine.KeyRemoval
import dev.nercone.replayintegrity.engine.KeyRemovalSettings
import dev.nercone.replayintegrity.engine.KeyboxPolicy
import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.engine.TargetScope
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.net.KeyboxSource
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stored settings must survive updates of the application in both directions. */
class SettingsTest {
    val json = Settings.JSON

    @Test
    fun valuesRoundTrip() {
        val values = Settings.Values(
            privilege = PrivilegeChoice.ROOT,
            autoKeybox = false,
            refreshHours = 12,
            extraPackages = listOf("com.example"),
            targetMode = TargetMode.GENERATE,
            spoofOverrides = mapOf("spoofProvider" to true),
            lastRefreshProblems = listOf("keybox: offline"),
        )
        assertEquals(values, json.decodeFromString(Settings.Values.serializer(), json.encodeToString(Settings.Values.serializer(), values)))
    }

    @Test
    fun anEarlierDocumentReadsWithDefaults() {
        val values = json.decodeFromString(Settings.Values.serializer(), """{"privilege":"SHIZUKU","applied":true}""")
        assertEquals(PrivilegeChoice.SHIZUKU, values.privilege)
        assertTrue(values.applied)
        assertEquals(Settings.Values().copy(privilege = PrivilegeChoice.SHIZUKU, applied = true), values)
    }

    @Test
    fun aLaterDocumentReadsWithoutItsNewFields() {
        val values = json.decodeFromString(Settings.Values.serializer(), """{"refreshHours":3,"aSettingOfALaterVersion":{"x":1},"targetMode":"aModeOfALaterVersion"}""")
        assertEquals(3, values.refreshHours)
        assertEquals("an unknown value falls back to the default", TargetMode.AUTO, values.targetMode)
    }

    @Test
    fun aDocumentWithTheOldKeyboxUrlFieldsMigratesToSources() {
        // A document written before sources carried their own settings held only URLs. Each
        // migrates to a source; the default mirror keeps the leniency it had implicitly, and any
        // other URL migrates strict, so an update changes no behavior.
        val values = Settings.decode("""{"keyboxUrl":"${Downloader.DEFAULT_KEYBOX_URL}","extraKeyboxUrls":["https://other.example/key"]}""")
        assertEquals(
            listOf(KeyboxSource(Downloader.DEFAULT_KEYBOX_URL, lenient = true), KeyboxSource("https://other.example/key", lenient = false)),
            values.keyboxSources,
        )
        // A user's own primary URL migrates strict.
        assertEquals(listOf(KeyboxSource("https://mirror.example/key", lenient = false)), Settings.decode("""{"keyboxUrl":"https://mirror.example/key"}""").keyboxSources)
        // A document from before any keybox source existed falls back to the default seed.
        assertEquals(Downloader.DEFAULT_KEYBOX_SOURCES, Settings.decode("""{"refreshHours":3}""").keyboxSources)
        assertEquals("the Play stack generates its keys by default", TargetMode.GENERATE, values.playTargetMode)
    }

    @Test
    fun aModeChosenForEveryTargetBeforeKeepsApplyingToThePlayStack() {
        assertEquals(TargetMode.PATCH, Settings.decode("""{"targetMode":"patch"}""").playTargetMode)
        assertEquals(TargetMode.GENERATE, Settings.decode("""{"targetMode":"auto"}""").playTargetMode)
        assertEquals("a stored Play mode wins", TargetMode.AUTO, Settings.decode("""{"targetMode":"patch","playTargetMode":"auto"}""").playTargetMode)
    }

    @Test
    fun keyboxSourcesAreTriedInOrderWithoutRepeats() {
        val values = Settings.Values(keyboxSources = listOf(
            KeyboxSource("https://a.example/key", lenient = true),
            KeyboxSource("https://b.example/key"),
            KeyboxSource("https://a.example/key"),
            KeyboxSource("https://c.example/key"),
        ))
        assertEquals(
            listOf(KeyboxSource("https://a.example/key", lenient = true), KeyboxSource("https://b.example/key"), KeyboxSource("https://c.example/key")),
            values.orderedKeyboxSources(),
        )
    }

    @Test
    fun leniencyIsAPerSourceSettingThatRoundTrips() {
        // Leniency is each source's own setting, honored on any source — not derived from the URL.
        val values = Settings.Values(keyboxSources = listOf(
            KeyboxSource("https://custom.example/key", lenient = true),
            KeyboxSource(Downloader.DEFAULT_KEYBOX_URL, lenient = false),
        ))
        assertEquals(values, json.decodeFromString(Settings.Values.serializer(), json.encodeToString(Settings.Values.serializer(), values)))
        assertTrue("a user source can be lenient", values.keyboxSources[0].lenient)
        assertTrue("the default mirror's URL is not special-cased", !values.keyboxSources[1].lenient)
        // A fresh install seeds the default mirror, lenient.
        assertEquals(listOf(KeyboxSource(Downloader.DEFAULT_KEYBOX_URL, lenient = true)), Settings.Values().keyboxSources)
    }

    @Test
    fun theEngineReceivesOnlyItsSettings() {
        val engine = Settings.Values(excludedPackages = listOf("com.game"), spoofOverrides = mapOf("spoofBuild" to false)).engine()
        assertEquals(listOf("com.game"), engine.excludedPackages)
        assertEquals(mapOf("spoofBuild" to false), engine.overrides())
        assertEquals(TargetMode.GENERATE, engine.playTargetMode)
        assertEquals(TargetMode.AUTO, Settings.Values(playTargetMode = TargetMode.AUTO).engine().playTargetMode)
    }

    @Test
    fun aDocumentOfAnEarlierVersionReadsAsTheBalancedProtection() {
        // A user who never changed these settings keeps the safe defaults after the update.
        val values = Settings.decode("""{"privilege":"ROOT","applied":true,"restartOnChange":true}""")
        assertEquals(Protection.BALANCED, Protection.of(values))
        assertEquals(Protection.DEFAULT, Protection.of(Settings.Values()))
    }

    @Test
    fun theDefaultsKeepEveryKeyThatMayHoldWhatTheUserEnrolled() {
        val values = Settings.Values()
        assertEquals(KeyRemoval.WHEN_REPLACED, values.keyRemoval.integrity)
        assertEquals(KeyRemoval.NEVER, values.keyRemoval.play)
        assertEquals(KeyRemoval.NEVER, values.keyRemoval.applications)
        assertEquals(Settings.KeyboxReplacement.WHEN_NEEDED, values.keyboxReplacement)
        assertEquals(KeyboxPolicy.WhenNeeded(Settings.DEFAULT_EXPIRY_MARGIN_HOURS), values.keyboxPolicy())
        assertEquals(KeyboxPolicy.NoDowngrade, values.copy(keyboxReplacement = Settings.KeyboxReplacement.NO_DOWNGRADE).keyboxPolicy())
    }

    @Test
    fun aProtectionSetsItsSettingsAndKeepsTheOthers() {
        val values = Settings.Values(refreshHours = 12, extraPackages = listOf("com.example"))
        for (protection in Protection.entries) {
            val chosen = protection.applyTo(values)
            assertEquals(protection, Protection.of(chosen))
            assertEquals(12, chosen.refreshHours)
            assertEquals(listOf("com.example"), chosen.extraPackages)
        }
        val integrity = Protection.INTEGRITY.applyTo(values)
        assertEquals(KeyRemovalSettings(KeyRemoval.WHEN_REPLACED, KeyRemoval.WHEN_REPLACED, KeyRemoval.WHEN_REPLACED, integrityPatch = true), integrity.keyRemoval)
        assertEquals(TargetScope.PLAY_AND_WALLETS, Protection.SAFETY.applyTo(values).targetScope)
    }

    @Test
    fun anAdjustedSettingMatchesNoProtection() {
        val adjusted = Protection.BALANCED.applyTo(Settings.Values()).let { it.copy(keyRemoval = it.keyRemoval.copy(play = KeyRemoval.WHEN_UNUSABLE)) }
        assertNull(Protection.of(adjusted))
    }

    @Test
    fun theEngineReceivesTheSafetySettings() {
        val values = Settings.Values(targetScope = TargetScope.PLAY, endBackgroundApplications = true, keyRemoval = KeyRemovalSettings(applications = KeyRemoval.WHEN_UNUSABLE))
        val engine = values.engine()
        assertEquals(TargetScope.PLAY, engine.targetScope)
        assertTrue(engine.endBackgroundApplications)
        assertEquals(KeyRemoval.WHEN_UNUSABLE, engine.keyRemoval.applications)
    }
}
