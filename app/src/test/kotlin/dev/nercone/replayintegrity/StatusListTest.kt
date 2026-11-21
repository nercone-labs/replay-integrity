package dev.nercone.replayintegrity

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A downloaded certificate status list replaces the cached copy only when it has the shape of
 * the list Google publishes (https://android.googleapis.com/attestation/status): a JSON object
 * whose `entries` is an object of serial numbers.
 */
class StatusListTest {
    @Test
    fun theShapeOfTheListIsAccepted() {
        assertTrue(Replay.isStatusList("""{"entries":{"2c8cdddfd5e03bfc":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""".toByteArray()))
        assertTrue(Replay.isStatusList("""{"entries":{}}""".toByteArray()))
    }

    @Test
    fun anythingElseIsRefused() {
        for (text in listOf("", "<html>error</html>", "[]", "{}", """{"entries":[]}""", """{"entries":null}""", """{"entries":{""")) {
            assertFalse(text, Replay.isStatusList(text.toByteArray()))
        }
    }
}
