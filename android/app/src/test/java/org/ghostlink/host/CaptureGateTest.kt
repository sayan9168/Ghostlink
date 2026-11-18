package org.ghostlink.host

import org.junit.Assert.*
import org.junit.Test

class CaptureGateTest {
    @Test fun noUnsolicitedApproval() {
        val gate = CaptureGate()
        assertFalse(gate.resolve(true))
        assertEquals(CaptureGate.State.IDLE, gate.state)
    }
    @Test fun denialAllowsFreshRequest() {
        val gate = CaptureGate()
        assertTrue(gate.request())
        assertFalse(gate.request())
        assertFalse(gate.resolve(false))
        assertTrue(gate.request())
    }
    @Test fun captureRequiresFreshApprovalAfterStop() {
        val gate = CaptureGate()
        assertTrue(gate.request())
        assertTrue(gate.resolve(true))
        assertFalse(gate.request())
        assertFalse(gate.resolve(true))
        gate.stop()
        assertFalse(gate.resolve(true))
        assertTrue(gate.request())
        assertTrue(gate.resolve(true))
    }
}
