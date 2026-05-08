package ai.synheart.auth

import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.SynheartAuthError
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class AuthStateTest {

    @Test
    fun `unregistered can transition to challengeReceived`() {
        assertTrue(DeviceAuthState.UNREGISTERED.canTransition(DeviceAuthState.CHALLENGE_RECEIVED))
    }

    @Test
    fun `challengeReceived can transition to keyReady`() {
        assertTrue(DeviceAuthState.CHALLENGE_RECEIVED.canTransition(DeviceAuthState.KEY_READY))
    }

    @Test
    fun `keyReady can transition to registering`() {
        assertTrue(DeviceAuthState.KEY_READY.canTransition(DeviceAuthState.REGISTERING))
    }

    @Test
    fun `registering can transition to registered`() {
        assertTrue(DeviceAuthState.REGISTERING.canTransition(DeviceAuthState.REGISTERED))
    }

    @Test
    fun `registering can transition to unregistered on failure`() {
        assertTrue(DeviceAuthState.REGISTERING.canTransition(DeviceAuthState.UNREGISTERED))
    }

    @Test
    fun `registered can transition to registering for rotation`() {
        assertTrue(DeviceAuthState.REGISTERED.canTransition(DeviceAuthState.REGISTERING))
    }

    @Test
    fun `registered can transition to keyInvalid`() {
        assertTrue(DeviceAuthState.REGISTERED.canTransition(DeviceAuthState.KEY_INVALID))
    }

    @Test
    fun `keyInvalid can transition to unregistered`() {
        assertTrue(DeviceAuthState.KEY_INVALID.canTransition(DeviceAuthState.UNREGISTERED))
    }

    @Test
    fun `invalid transition throws`() {
        assertThrows(SynheartAuthError.InvalidStateTransition::class.java) {
            DeviceAuthState.UNREGISTERED.transition(DeviceAuthState.REGISTERED)
        }
    }

    @Test
    fun `unregistered cannot skip to registered`() {
        assertFalse(DeviceAuthState.UNREGISTERED.canTransition(DeviceAuthState.REGISTERED))
    }

    @Test
    fun `transition returns new state`() {
        val newState = DeviceAuthState.UNREGISTERED.transition(DeviceAuthState.CHALLENGE_RECEIVED)
        assertEquals(DeviceAuthState.CHALLENGE_RECEIVED, newState)
    }

    @Test
    fun `fromValue roundtrip`() {
        for (state in DeviceAuthState.entries) {
            assertEquals(state, DeviceAuthState.fromValue(state.value))
        }
    }

    @Test
    fun `fromValue returns null for unknown`() {
        assertNull(DeviceAuthState.fromValue("nonexistent"))
    }
}
