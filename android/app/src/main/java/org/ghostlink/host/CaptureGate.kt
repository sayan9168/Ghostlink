package org.ghostlink.host

/** Local-only lifecycle gate: projection grants must be fresh and are never persisted. */
internal class CaptureGate {
    enum class State { IDLE, AWAITING_CONSENT, CAPTURING }
    var state = State.IDLE
        private set

    fun request(): Boolean {
        if (state != State.IDLE) return false
        state = State.AWAITING_CONSENT
        return true
    }

    fun resolve(approved: Boolean): Boolean {
        if (state != State.AWAITING_CONSENT) return false
        state = if (approved) State.CAPTURING else State.IDLE
        return approved
    }

    fun stop() { state = State.IDLE }
}
