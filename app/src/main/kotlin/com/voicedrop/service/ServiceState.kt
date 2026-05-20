package com.voicedrop.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object ServiceState {
    enum class State { IDLE, RECORDING, SENDING }

    data class RecordingState(
        val state: State,
        /**
         * Contact ids being recorded for. Empty when [state] == IDLE.
         * Length == 1 for the existing per-contact widget and picker fallback;
         * length > 1 for the tile or All-widget fanning out across a set.
         */
        val activeContactIds: List<String>,
        val startedAtElapsedRealtime: Long = 0L,
        val startedAtWallClock: Long = 0L,
    )

    private val _recordingState = MutableStateFlow(RecordingState(State.IDLE, emptyList()))
    val recordingState: StateFlow<RecordingState> = _recordingState

    private val _playingUuid = MutableStateFlow<String?>(null)
    val playingUuid: StateFlow<String?> = _playingUuid

    fun updateState(
        state: State,
        contactIds: List<String>,
        startedAtElapsedRealtime: Long = 0L,
        startedAtWallClock: Long = 0L,
    ) {
        _recordingState.value = RecordingState(
            state,
            contactIds,
            startedAtElapsedRealtime,
            startedAtWallClock,
        )
    }

    fun setPlayingUuid(uuid: String?) {
        _playingUuid.value = uuid
    }
}
