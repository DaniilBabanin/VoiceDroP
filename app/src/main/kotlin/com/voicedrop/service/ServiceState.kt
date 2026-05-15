package com.voicedrop.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object ServiceState {
    enum class State { IDLE, RECORDING, SENDING }

    data class RecordingState(
        val state: State,
        val activeContactId: String?,
        val startedAtElapsedRealtime: Long = 0L,
        val startedAtWallClock: Long = 0L,
    )

    private val _recordingState = MutableStateFlow(RecordingState(State.IDLE, null))
    val recordingState: StateFlow<RecordingState> = _recordingState

    private val _playingUuid = MutableStateFlow<String?>(null)
    val playingUuid: StateFlow<String?> = _playingUuid

    fun updateState(
        state: State,
        contactId: String?,
        startedAtElapsedRealtime: Long = 0L,
        startedAtWallClock: Long = 0L,
    ) {
        _recordingState.value = RecordingState(
            state,
            contactId,
            startedAtElapsedRealtime,
            startedAtWallClock,
        )
    }

    fun setPlayingUuid(uuid: String?) {
        _playingUuid.value = uuid
    }
}
