package dev.nercone.replayintegrity.net

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DownloaderTest {
    @Test
    fun onlyHttpsUrlsWithAHostAreAccepted() {
        assertTrue(Downloader.isAcceptable("https://example.com/key"))
        assertTrue(Downloader.isAcceptable(Downloader.DEFAULT_KEYBOX_URL))
        assertTrue(Downloader.isAcceptable(Downloader.DEFAULT_FINGERPRINT_URL))
        assertFalse(Downloader.isAcceptable("http://example.com/key"))
        assertFalse(Downloader.isAcceptable("file:///sdcard/keybox.xml"))
        assertFalse(Downloader.isAcceptable("https://"))
        assertFalse(Downloader.isAcceptable("not a url"))
        assertFalse(Downloader.isAcceptable(""))
    }

    @Test
    fun xmlIsToldFromBase64() {
        assertTrue(Downloader.looksLikeXML("<?xml version=\"1.0\"?><AndroidAttestation/>".toByteArray()))
        assertTrue(Downloader.looksLikeXML("﻿\n  <AndroidAttestation/>".toByteArray()))
        assertFalse(Downloader.looksLikeXML("PD94bWwgdmVyc2lvbj0iMS4wIj8+".toByteArray()))
        assertFalse(Downloader.looksLikeXML(ByteArray(0)))
    }

    private val keybox = "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes></AndroidAttestation>".toByteArray()

    private fun gzip(bytes: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(bytes) } }.toByteArray()

    private fun zip(vararg entries: Pair<String, ByteArray>): ByteArray =
        ByteArrayOutputStream().also { out ->
            ZipOutputStream(out).use { zip ->
                for ((name, bytes) in entries) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(bytes)
                    zip.closeEntry()
                }
            }
        }.toByteArray()

    @Test
    fun plainXmlIsReturnedUnchanged() {
        assertArrayEquals(keybox, Downloader.decodeKeybox(keybox))
    }

    @Test
    fun base64OfAKeyboxIsDecoded() {
        assertArrayEquals(keybox, Downloader.decodeKeybox(Base64.getEncoder().encode(keybox)))
        // URL-safe base64 is accepted too.
        assertArrayEquals(keybox, Downloader.decodeKeybox(Base64.getUrlEncoder().encode(keybox)))
    }

    @Test
    fun gzipAndZipAndNestedContainersAreUnwrapped() {
        assertArrayEquals(keybox, Downloader.decodeKeybox(gzip(keybox)))
        assertArrayEquals(keybox, Downloader.decodeKeybox(zip("keybox.xml" to keybox)))
        // base64 of a gzip of the keybox: every layer is unwrapped in turn.
        assertArrayEquals(keybox, Downloader.decodeKeybox(Base64.getEncoder().encode(gzip(keybox))))
    }

    @Test
    fun aZipMustHoldExactlyOneFile() {
        assertThrows(java.io.IOException::class.java) {
            Downloader.decodeKeybox(zip("a.xml" to keybox, "b.xml" to keybox))
        }
    }

    @Test
    fun contentThatIsNotAKeyboxIsRejected() {
        // An HTML error page a mirror might serve: it is not XML and not a container.
        assertThrows(java.io.IOException::class.java) { Downloader.decodeKeybox("not a keybox".toByteArray()) }
    }

    @Test
    fun aDeclaredFormatStripsThatOuterContainerThenDetectsTheRest() {
        // The declared format names the outer container; a further container inside is still
        // detected on its own, so base64 of a gzip is read when the source is set to base64.
        assertArrayEquals(keybox, Downloader.decodeKeybox(keybox, KeyboxFormat.XML))
        assertArrayEquals(keybox, Downloader.decodeKeybox(Base64.getEncoder().encode(keybox), KeyboxFormat.BASE64))
        assertArrayEquals(keybox, Downloader.decodeKeybox(gzip(keybox), KeyboxFormat.GZIP))
        assertArrayEquals(keybox, Downloader.decodeKeybox(zip("keybox.xml" to keybox), KeyboxFormat.ZIP))
        assertArrayEquals(keybox, Downloader.decodeKeybox(Base64.getEncoder().encode(gzip(keybox)), KeyboxFormat.BASE64))
    }

    @Test
    fun aDownloadThatIsNotTheDeclaredFormatIsRejected() {
        assertThrows(java.io.IOException::class.java) { Downloader.decodeKeybox(keybox, KeyboxFormat.BASE64) }
        assertThrows(java.io.IOException::class.java) { Downloader.decodeKeybox(gzip(keybox), KeyboxFormat.XML) }
        assertThrows(java.io.IOException::class.java) { Downloader.decodeKeybox(Base64.getEncoder().encode(keybox), KeyboxFormat.ZIP) }
    }

    @Test
    fun plainTextIsNotMistakenForBase64() {
        // Text with spaces and punctuation is outside the base64 alphabet, so it is not decoded.
        assertEquals(null, Downloader.decodeBase64("this is not base64!".toByteArray()))
        // XML is handled before base64, so a keybox is never run through the base64 decoder.
        assertEquals(null, Downloader.decodeBase64(keybox))
    }

    @Test
    fun anUncachedURLKeepsItsTargetAndDiffersForEachNonce() {
        val first = Downloader.uncachedURL(Downloader.STATUS_LIST_URL, 1)
        val second = Downloader.uncachedURL(Downloader.STATUS_LIST_URL, 2)
        assertNotEquals(first, second)
        assertTrue(first.startsWith(Downloader.STATUS_LIST_URL + "?"))
        assertTrue(Downloader.isAcceptable(first))
        assertEquals(java.net.URL(Downloader.STATUS_LIST_URL).host, java.net.URL(first).host)
        assertEquals(java.net.URL(Downloader.STATUS_LIST_URL).path, java.net.URL(first).path)
        assertTrue(Downloader.uncachedURL("https://example.com/a?b=c", 1).startsWith("https://example.com/a?b=c&"))
    }
}
