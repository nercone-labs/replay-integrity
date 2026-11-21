package dev.nercone.replayintegrity.engine

import dev.nercone.replayintegrity.privilege.CommandResult
import dev.nercone.replayintegrity.privilege.ProcessRunner
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

// How the application talks with its engine, the same in TypeFace Droplet and Replay Integrity:
// every command prints one JSON object (`EngineResponse`) as its last line of output, with the
// log of the command (`log.rs` of the engine, which both engines share). The types of the results
// belong to each application (`EngineModels.kt`).

@Serializable
enum class LogLevel {
    @SerialName("info") INFO,
    @SerialName("warning") WARNING,
    @SerialName("error") ERROR,
}

@Serializable
data class LogLine(val time: Long, val level: LogLevel = LogLevel.INFO, val message: String)

@Serializable
data class EngineError(val kind: String, val message: String)

/** The one JSON object every engine command prints: its result or its error, and its log. */
@Serializable
data class EngineResponse(val ok: Boolean = false, val result: JsonElement? = null, val error: EngineError? = null, val log: List<LogLine> = emptyList())

/** A failed engine command, with the engine log of the attempt. `kind` is the kind of the engine error, or one of the kinds below. */
class EngineException(val kind: String, message: String, val log: List<LogLine>) : Exception(message) {
    companion object {
        /** The engine runs as root, but the root manager removed the capabilities it needs. */
        const val RESTRICTED = "restricted"

        /** The engine did not finish in time. */
        const val TIMEOUT = "timeout"

        /** The engine could not be started, or printed no response the application can read. */
        const val OUTPUT = "output"

        /** The engine failed without saying why. */
        const val UNKNOWN = "unknown"
    }
}

/** The successful result of an engine command, with the engine log. */
data class EngineResult<T>(val value: T, val log: List<LogLine>)

/** Reads the output of the engine. Each failure becomes an `EngineException`, never a crash of the application. */
object EngineProtocol {
    /** How much of the output a message quotes. */
    const val MESSAGE_LENGTH = 500

    /**
     * The result of a run of the engine. A run that could not start or that timed out before it
     * printed its response fails with that reason; `stderr` explains a missing or invalid
     * response, such as the refusal of `su`, which prints nothing on the output.
     */
    fun <T> read(json: Json, output: CommandResult, serializer: KSerializer<T>): EngineResult<T> {
        if (output.exitCode == ProcessRunner.START_FAILURE_EXIT_CODE && output.stdout.isBlank()) {
            throw EngineException(EngineException.OUTPUT, "the engine could not be started: ${output.stderr.take(MESSAGE_LENGTH)}", emptyList())
        }
        if (output.exitCode == ProcessRunner.TIMEOUT_EXIT_CODE && output.stdout.isBlank()) {
            throw EngineException(EngineException.TIMEOUT, "the engine did not finish in time: ${output.stderr.take(MESSAGE_LENGTH)}", emptyList())
        }
        return result(json, decode(json, output.stdout, output.stderr), serializer)
    }

    /** The response the engine printed last in `stdout`. */
    fun decode(json: Json, stdout: String, stderr: String): EngineResponse {
        val line = stdout.lineSequence().lastOrNull { it.startsWith("{") }
            ?: throw EngineException(EngineException.OUTPUT, "the engine printed no result: ${(stdout + "\n" + stderr).trim().take(MESSAGE_LENGTH)}", emptyList())
        return try {
            json.decodeFromString(EngineResponse.serializer(), line)
        } catch (error: SerializationException) {
            throw EngineException(EngineException.OUTPUT, "the engine printed an invalid result: ${error.message}", emptyList())
        } catch (error: IllegalArgumentException) {
            throw EngineException(EngineException.OUTPUT, "the engine printed an invalid result: ${error.message}", emptyList())
        }
    }

    /** The value of a successful `response`, decoded with `serializer`; the error of a failed one. */
    fun <T> result(json: Json, response: EngineResponse, serializer: KSerializer<T>): EngineResult<T> {
        val error = response.error
        if (!response.ok || error != null) {
            throw EngineException(error?.kind ?: EngineException.UNKNOWN, error?.message ?: "the engine failed", response.log)
        }
        val value = response.result ?: throw EngineException(EngineException.OUTPUT, "the engine returned no result", response.log)
        return try {
            EngineResult(json.decodeFromJsonElement(serializer, value), response.log)
        } catch (error: SerializationException) {
            throw EngineException(EngineException.OUTPUT, "the engine returned an unexpected result: ${error.message}", response.log)
        } catch (error: IllegalArgumentException) {
            throw EngineException(EngineException.OUTPUT, "the engine returned an unexpected result: ${error.message}", response.log)
        }
    }
}
