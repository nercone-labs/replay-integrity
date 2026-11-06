package dev.nercone.replayintegrity.net

import android.util.Base64
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A file fetched from the network, with where it came from. */
data class Fetched(val bytes: ByteArray, val source: String)

/**
 * Downloads the inputs the engine checks and installs: the attestation keybox, a Pixel
 * fingerprint and Google's certificate status list. The application has ordinary TLS, so no
 * special networking is needed here; the engine does the parsing and the trust decisions.
 *
 * The keybox mirror and the fingerprint source are those the AlwaysStrong module uses. The URLs
 * can be overridden, so the user is never tied to one mirror.
 */
class Downloader(
    val keyboxUrl: String = DEFAULT_KEYBOX_URL,
    val fingerprintUrl: String = DEFAULT_FINGERPRINT_URL,
) {
    /**
     * The keybox, base64-decoded. The mirror serves the keybox as base64 of the XML; it is
     * decoded here and the engine checks that it is a keybox before anything is installed.
     */
    suspend fun keybox(): Fetched {
        val encoded = fetch(keyboxUrl)
        val decoded = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (error: IllegalArgumentException) {
            throw IOException("the keybox mirror did not return base64", error)
        }
        if (decoded.isEmpty()) throw IOException("the keybox mirror returned an empty keybox")
        return Fetched(decoded, keyboxUrl)
    }

    suspend fun fingerprint(): Fetched = Fetched(fetch(fingerprintUrl), fingerprintUrl)

    suspend fun statusList(): Fetched = Fetched(fetch(STATUS_LIST_URL), STATUS_LIST_URL)

    /** Downloads a URL into memory, following redirects, with bounded timeouts. */
    suspend fun fetch(url: String): ByteArray = withContext(Dispatchers.IO) {
        var current = url
        for (redirect in 0 until MAX_REDIRECTS) {
            val connection = (URL(current).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MILLIS
                readTimeout = READ_TIMEOUT_MILLIS
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", USER_AGENT)
                setRequestProperty("Accept", "*/*")
            }
            try {
                val code = connection.responseCode
                if (code in 300..399) {
                    val location = connection.getHeaderField("Location") ?: throw IOException("a redirect without a location from $current")
                    val next = URL(URL(current), location)
                    // Never follow a redirect that drops from HTTPS to HTTP: a network attacker
                    // could otherwise strip the transport security of these fetches.
                    if (URL(current).protocol == "https" && next.protocol != "https") {
                        throw IOException("$current redirected to a non-HTTPS URL")
                    }
                    current = next.toString()
                    continue
                }
                if (code != HttpURLConnection.HTTP_OK) {
                    throw IOException("$current returned HTTP $code")
                }
                val bytes = connection.inputStream.use { it.readLimited(MAX_BYTES) }
                if (bytes.isEmpty()) throw IOException("$current returned no data")
                return@withContext bytes
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("too many redirects from $url")
    }

    companion object {
        /** The keybox mirror AlwaysStrong uses; served over HTTPS as base64 of the keybox XML. */
        const val DEFAULT_KEYBOX_URL = "https://evoker.qzz.io/key"

        /**
         * A STRONG-capable Pixel fingerprint: the Pixel 6a (`bluejay`) canary build from the
         * public canary repository. Only devices that launched on Android 12 still earn STRONG,
         * because Google cross-checks the claimed first-API level against the real launch OS.
         */
        const val DEFAULT_FINGERPRINT_URL = "https://raw.githubusercontent.com/Vagelis1608/get_the_canary_miner/main/devices/bluejay.pif.prop"

        /** Google's certificate revocation status list. */
        const val STATUS_LIST_URL = "https://android.googleapis.com/attestation/status"

        const val CONNECT_TIMEOUT_MILLIS = 20_000
        const val READ_TIMEOUT_MILLIS = 30_000
        const val MAX_REDIRECTS = 5
        /** A cap on a response body: the keybox and status list are well under a megabyte. */
        const val MAX_BYTES = 16 * 1024 * 1024
        const val USER_AGENT = "ReplayIntegrity"
    }
}

/** Reads at most [limit] bytes from the stream, failing if the body is longer. */
private fun InputStream.readLimited(limit: Int): ByteArray {
    val buffer = java.io.ByteArrayOutputStream()
    val chunk = ByteArray(16 * 1024)
    var total = 0
    while (true) {
        val read = read(chunk)
        if (read < 0) break
        total += read
        if (total > limit) throw IOException("the response is larger than $limit bytes")
        buffer.write(chunk, 0, read)
    }
    return buffer.toByteArray()
}
