package com.voicedrop.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object ServiceState {
    enum class State { IDLE, RECORDING, SENDING }

    data class RecordingState(val state: State, val activeContactId: String?)

    private val _recordingState = MutableStateFlow(RecordingState(State.IDLE, null))
    val recordingState: StateFlow<RecordingState> = _recordingState

    fun updateState(state: State, contactId: String?) {
        _recordingState.value = RecordingState(state, contactId)
    }
}
