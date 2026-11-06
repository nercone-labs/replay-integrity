package dev.nercone.replayintegrity.privilege

/** Which privilege the user chose. */
enum class PrivilegeChoice { AUTOMATIC, SHIZUKU, ROOT }

/**
 * The privilege to use, with the status of every candidate for display. `declined` tells
 * whether a permission was asked for and still has not been granted.
 */
data class PrivilegeSelection(
    val privilege: Privilege?,
    val statuses: List<Pair<Privilege.Kind, PrivilegeStatus>>,
    val declined: Boolean = false,
)

/**
 * Chooses the privilege to run the engine with. Automatically, Shizuku (and Sui, which
 * provides the Shizuku interface) is preferred over `su`, because it needs no shell and keeps
 * a single connection; `su` is used when Shizuku cannot run commands as root.
 *
 * With `interactive`, a candidate that needs the user's permission asks for it before the next
 * candidate is tried, so that the preference for Shizuku is not silently given up in favour of
 * `su`. Callers that run without the user, such as the boot worker, leave it `false`, so that
 * no dialog opens.
 */
class PrivilegeSelector(val shizuku: Privilege, val root: Privilege) {
    suspend fun select(choice: PrivilegeChoice, interactive: Boolean = false): PrivilegeSelection {
        val candidates = when (choice) {
            PrivilegeChoice.AUTOMATIC -> listOf(shizuku, root)
            PrivilegeChoice.SHIZUKU -> listOf(shizuku)
            PrivilegeChoice.ROOT -> listOf(root)
        }
        val statuses = mutableListOf<Pair<Privilege.Kind, PrivilegeStatus>>()
        var declined = false
        for (candidate in candidates) {
            var status = candidate.status()
            if (interactive && status == PrivilegeStatus.PermissionRequired) {
                status = candidate.requestPermission()
                if (status == PrivilegeStatus.PermissionRequired) declined = true
            }
            statuses += candidate.kind to status
            if (status is PrivilegeStatus.Available) return PrivilegeSelection(candidate, statuses, declined)
        }
        return PrivilegeSelection(null, statuses, declined)
    }
}
