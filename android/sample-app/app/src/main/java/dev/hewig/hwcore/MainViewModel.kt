package dev.hewig.hwcore

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import uniffi.hwcore.*

/** Screens / steps in the sample app flow. */
enum class AppScreen {
    Home,
    Scanning,
    Connecting,
    Pairing,
    Ready,
}

/** Observable UI state. */
data class UiState(
    val screen: AppScreen = AppScreen.Home,
    val log: List<String> = emptyList(),
    val devices: List<BleDiscoveredDevice> = emptyList(),
    val sessionState: SessionState? = null,
    val pairingPrompt: PairingPrompt? = null,
    val address: String? = null,
    val signResult: String? = null,
    val error: String? = null,
    val isBusy: Boolean = false,
)

class MainViewModel : ViewModel() {

    var ui by mutableStateOf(UiState())
        private set

    private var bleManager: BleManagerHandle? = null
    private var workflow: BleWorkflowHandle? = null

    // ArrayDeque for O(1) amortized appends — avoids O(N²) copy-on-every-log issue
    private val logEntries = ArrayDeque<String>()

    private val hostConfig: HostConfig by lazy {
        hostConfigNew("HWCoreSampleApp", "hw-core-android-sample")
    }

    private val retryPolicy: SessionRetryPolicy by lazy {
        sessionRetryPolicyDefault()
    }

    // -- Logging helpers --

    private fun log(msg: String) {
        logEntries.addLast(msg)
        ui = ui.copy(log = logEntries.toList())
    }

    private fun setError(msg: String) {
        log("ERROR: $msg")
        ui = ui.copy(error = msg, isBusy = false)
    }

    // -- BLE Scan --

    fun scan() {
        ui = ui.copy(
            screen = AppScreen.Scanning,
            devices = emptyList(),
            error = null,
            isBusy = true,
        )
        log("Scanning for Trezor devices...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                if (bleManager == null) {
                    bleManager = BleManagerHandle.new()
                    log("BLE manager initialized")
                }
                val mgr = bleManager ?: return@launch
                val found = mgr.discoverTrezor(5000uL)
                log("Found ${found.size} device(s)")
                ui = ui.copy(
                    devices = found,
                    isBusy = false,
                )
            } catch (e: Exception) {
                setError("Scan failed: ${e.message}")
            }
        }
    }

    // -- Connect to device --

    fun connectDevice(device: BleDiscoveredDevice) {
        val info = device.info()
        log("Connecting to ${info.name ?: info.id}...")
        ui = ui.copy(
            screen = AppScreen.Connecting,
            error = null,
            isBusy = true,
        )

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = device.connectReadyWorkflowWithPolicy(
                    config = hostConfig,
                    storagePath = null,
                    tryToUnlock = true,
                    retryPolicy = retryPolicy,
                )
                workflow = wf
                val state = wf.sessionState()
                log("Session phase: ${state.phase}")
                ui = ui.copy(sessionState = state, isBusy = false)

                when {
                    state.canGetAddress -> {
                        log("Session ready")
                        ui = ui.copy(screen = AppScreen.Ready)
                    }
                    state.requiresPairingCode -> {
                        log("Pairing required")
                        startPairing()
                    }
                    else -> {
                        log("Session phase: ${state.phase}, advancing...")
                        advanceSession()
                    }
                }
            } catch (e: Exception) {
                setError("Connect failed: ${e.message}")
            }
        }
    }

    // -- Pairing --

    private suspend fun startPairing() {
        try {
            val wf = workflow ?: return
            val prompt = wf.pairingStart()
            log("Pairing prompt: ${prompt.message}")
            ui = ui.copy(
                screen = AppScreen.Pairing,
                pairingPrompt = prompt,
                isBusy = false,
            )
        } catch (e: HwCoreException) {
            setError("Pairing start failed: ${e.message}")
        }
    }

    fun submitPairingCode(code: String) {
        log("Submitting pairing code...")
        ui = ui.copy(isBusy = true, error = null)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch
                val progress = wf.pairingSubmitCode(code)
                log("Pairing progress: ${progress.kind} - ${progress.message}")

                when (progress.kind) {
                    PairingProgressKind.AWAITING_CONNECTION_CONFIRMATION -> {
                        log("Confirm connection on device...")
                        val confirm = wf.pairingConfirmConnection()
                        log("Confirm result: ${confirm.kind} - ${confirm.message}")
                        if (confirm.kind == PairingProgressKind.COMPLETED) {
                            finishPairing()
                        }
                    }
                    PairingProgressKind.COMPLETED -> {
                        finishPairing()
                    }
                    else -> {
                        ui = ui.copy(isBusy = false)
                    }
                }
            } catch (e: Exception) {
                setError("Pairing failed: ${e.message}")
            }
        }
    }

    fun confirmConnection() {
        log("Confirming connection on device...")
        ui = ui.copy(isBusy = true, error = null)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch
                val progress = wf.pairingConfirmConnection()
                log("Confirm: ${progress.kind} - ${progress.message}")
                if (progress.kind == PairingProgressKind.COMPLETED) {
                    finishPairing()
                } else {
                    ui = ui.copy(isBusy = false)
                }
            } catch (e: HwCoreException) {
                setError("Confirm failed: ${e.message}")
            }
        }
    }

    private suspend fun finishPairing() {
        val wf = workflow ?: return
        log("Pairing complete, creating session...")
        try {
            wf.prepareReadySessionWithPolicy(true, retryPolicy)
            log("Session ready")
            val state = wf.sessionState()
            ui = ui.copy(
                screen = AppScreen.Ready,
                sessionState = state,
                isBusy = false,
            )
        } catch (e: HwCoreException) {
            setError("Session creation failed: ${e.message}")
        }
    }

    private suspend fun advanceSession() {
        val wf = workflow ?: return
        try {
            val hsState = wf.prepareChannelAndHandshake(true)
            when (hsState) {
                is SessionHandshakeState.Ready -> {
                    wf.prepareReadySessionWithPolicy(true, retryPolicy)
                    val state = wf.sessionState()
                    log("Session ready")
                    ui = ui.copy(
                        screen = AppScreen.Ready,
                        sessionState = state,
                        isBusy = false,
                    )
                }
                is SessionHandshakeState.PairingRequired -> {
                    log("Pairing required")
                    ui = ui.copy(pairingPrompt = hsState.prompt)
                    startPairing()
                }
                is SessionHandshakeState.ConnectionConfirmationRequired -> {
                    log("Connection confirmation required")
                    ui = ui.copy(
                        screen = AppScreen.Pairing,
                        pairingPrompt = hsState.prompt,
                        isBusy = false,
                    )
                }
            }
        } catch (e: HwCoreException) {
            setError("Session advance failed: ${e.message}")
        }
    }

    // -- Get ETH Address --

    fun getEthAddress() {
        log("Getting ETH address...")
        ui = ui.copy(address = null, error = null, isBusy = true)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch
                val config = chainConfig(Chain.ETHEREUM)
                val request = GetAddressRequest(
                    chain = Chain.ETHEREUM,
                    path = config.defaultPath,
                    showOnDevice = true,
                    includePublicKey = false,
                    chunkify = false,
                )
                val result = wf.getAddress(request)
                log("ETH address: ${result.address}")
                ui = ui.copy(address = result.address, isBusy = false)
            } catch (e: Exception) {
                setError("Get address failed: ${e.message}")
            }
        }
    }

    // -- Sign ETH Transaction --

    fun signEthTx() {
        log("Signing ETH transaction...")
        ui = ui.copy(signResult = null, error = null, isBusy = true)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch
                val config = chainConfig(Chain.ETHEREUM)
                val request = SignTxRequest(
                    chain = Chain.ETHEREUM,
                    path = config.defaultPath,
                    to = "0x000000000000000000000000000000000000dEaD",
                    value = "0x0",
                    nonce = "0x0",
                    gasLimit = "0x5208",
                    chainId = 1uL,
                    data = "0x",
                    maxFeePerGas = "0x3b9aca00",
                    maxPriorityFee = "0x59682f00",
                    accessList = emptyList(),
                    chunkify = false,
                )
                val result = wf.signTx(request)
                val sig = "v=${result.v}, r=${result.r.toHex()}, s=${result.s.toHex()}"
                log("Signature: $sig")
                val display = buildString {
                    appendLine("v = ${result.v}")
                    appendLine("r = ${result.r.toHex()}")
                    appendLine("s = ${result.s.toHex()}")
                    result.txHash?.let { appendLine("tx_hash = ${it.toHex()}") }
                    result.recoveredAddress?.let { appendLine("from = $it") }
                }
                ui = ui.copy(signResult = display, isBusy = false)
            } catch (e: Exception) {
                setError("Sign tx failed: ${e.message}")
            }
        }
    }

    // -- Cleanup --

    fun reset() {
        workflow?.destroy()
        workflow = null
        logEntries.clear()
        ui = UiState()
    }

    override fun onCleared() {
        workflow?.destroy()
        bleManager?.destroy()
        super.onCleared()
    }
}

private val HEX_CHARS = "0123456789abcdef".toCharArray()

/** O(N) hex encoding without String.format overhead — avoids format-string parsing per byte. */
private fun ByteArray.toHex(): String = buildString(size * 2) {
    for (b in this@toHex) {
        val i = b.toInt() and 0xff
        append(HEX_CHARS[i shr 4])
        append(HEX_CHARS[i and 0xf])
    }
}
