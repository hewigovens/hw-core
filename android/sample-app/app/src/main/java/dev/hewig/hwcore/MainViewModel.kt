package dev.hewig.hwcore

import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import uniffi.hwcore.*

/** Screens / steps in the sample app flow. */
enum class AppScreen {
    Home,
    Scanning,
    Connecting,
    Pairing,
    Ready,
}

private enum class PendingPairingFlow {
    PairOnly,
    ConnectReady,
}

/** Observable UI state. */
data class UiState(
    val screen: AppScreen = AppScreen.Home,
    val status: String = "Idle",
    val phaseSummary: String = "No session",
    val log: List<String> = emptyList(),
    val devices: List<BleDiscoveredDevice> = emptyList(),
    val selectedDeviceIndex: Int = 0,
    val sessionState: SessionState? = null,
    val hasWorkflow: Boolean = false,
    val pairingPrompt: PairingPrompt? = null,
    val selectedChain: Chain = Chain.ETHEREUM,
    val addressPathInput: String = DEFAULT_ETH_PATH,
    val showAddressOnDevice: Boolean = true,
    val includeAddressPublicKey: Boolean = false,
    val addressChunkify: Boolean = false,
    val ethSignPathInput: String = DEFAULT_ETH_PATH,
    val ethTo: String = "0x000000000000000000000000000000000000dead",
    val ethValue: String = "0x0",
    val ethNonce: String = "0x0",
    val ethGasLimit: String = "0x5208",
    val ethChainId: String = "1",
    val ethData: String = "0x",
    val ethMaxFeePerGas: String = "0x3b9aca00",
    val ethMaxPriorityFee: String = "0x59682f00",
    val ethChunkify: Boolean = false,
    val messageSignPathInput: String = DEFAULT_ETH_PATH,
    val messagePayload: String = "hello from hw-core",
    val messageIsHex: Boolean = false,
    val messageChunkify: Boolean = false,
    val solSignPathInput: String = DEFAULT_SOL_PATH,
    val solSerializedTxHex: String = DEFAULT_SOLANA_TX_HEX,
    val solChunkify: Boolean = false,
    val btcTxJsonInput: String = DEFAULT_BITCOIN_TX_JSON,
    val address: String? = null,
    val txSignResult: String? = null,
    val messageSignResult: String? = null,
    val error: String? = null,
    val isBusy: Boolean = false,
)

private const val DEFAULT_ETH_PATH = "m/44'/60'/0'/0/0"
private const val DEFAULT_BTC_PATH = "m/84'/0'/0'/0/0"
private const val DEFAULT_SOL_PATH = "m/44'/501'/0'/0'"
private const val SESSION_STEP_TIMEOUT_MS = 60_000L
private const val DEFAULT_APP_NAME = "hw-core/cli"
private const val UI_STATE_SNAPSHOT_FILE = "sample-ui-state.json"
private const val UI_STATE_SAVED_KEY = "sample_ui_state_json"

private const val DEFAULT_SOLANA_TX_HEX =
    "01000103dcf07724e5ed851704cc5e8528f4b08d3ebb6184d327c0ea17b88bb3aaa7c31a11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000222222222222222222222222222222222222222222222222222222222222222201020200010c020000000100000000000000"

private const val DEFAULT_BITCOIN_TX_JSON = """
{
  "version": 2,
  "lock_time": 0,
  "inputs": [
    {
      "path": "m/84'/0'/0'/0/0",
      "prev_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "prev_index": 0,
      "amount": "1000",
      "sequence": 4294967295,
      "script_type": "spendwitness"
    }
  ],
  "outputs": [
    {
      "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
      "amount": "900",
      "script_type": "paytoaddress"
    }
  ],
  "ref_txs": [
    {
      "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
      "version": 2,
      "lock_time": 0,
      "inputs": [
        {
          "prev_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "prev_index": 0,
          "script_sig": "",
          "sequence": 4294967295
        }
      ],
      "bin_outputs": [
        {
          "amount": "1000",
          "script_pubkey": "001400112233445566778899aabbccddeeff00112233"
        }
      ]
    }
  ]
}
"""

class MainViewModel(private val savedStateHandle: SavedStateHandle) : ViewModel() {

    private var uiState by mutableStateOf(UiState())
    var ui: UiState
        get() = uiState
        private set(value) {
            uiState = value
            persistUiSavedState()
            persistUiSnapshot()
        }

    private var bleManager: BleManagerHandle? = null
    private var workflow: BleWorkflowHandle? = null
    private var workflowEventsJob: Job? = null
    private var pendingPairingFlow: PendingPairingFlow? = null
    private var hostConfig: HostConfig? = null
    private var storagePath: String? = null
    private var appContext: Context? = null
    private var snapshotLoaded = false
    private var suspendSnapshotWrites = false

    // ArrayDeque for O(1) amortized appends — avoids O(N^2) copy-on-every-log issue.
    private val logEntries = ArrayDeque<String>()

    private val retryPolicy: SessionRetryPolicy by lazy {
        sessionRetryPolicyDefault()
    }

    init {
        val savedJson = savedStateHandle.get<String>(UI_STATE_SAVED_KEY)
        if (!savedJson.isNullOrBlank() && restoreUiFromJsonString(savedJson, "saved state")) {
            snapshotLoaded = true
        }
    }

    fun initialize(context: Context) {
        appContext = context.applicationContext
        if (!snapshotLoaded) {
            restoreUiSnapshot()
            snapshotLoaded = true
        }

        if (hostConfig != null) {
            return
        }

        val hostName = defaultHostName(context)
        hostConfig = hostConfigNew(hostName, DEFAULT_APP_NAME)
        storagePath = context.filesDir.resolve("thp-host.json").absolutePath
        log("Host configured: $hostName / $DEFAULT_APP_NAME")
    }

    // -- Logging helpers --

    private fun log(msg: String) {
        Log.d("HWCoreSample", msg)
        logEntries.addLast(msg)
        ui = ui.copy(log = logEntries.toList())
    }

    fun clearLogs() {
        logEntries.clear()
        ui = ui.copy(log = emptyList())
    }

    private fun snapshotJson(state: UiState): JSONObject =
        JSONObject().apply {
            put("screen", state.screen.name)
            put("status", state.status)
            put("phaseSummary", state.phaseSummary)
            put("selectedChain", state.selectedChain.name)
            put("addressPathInput", state.addressPathInput)
            put("showAddressOnDevice", state.showAddressOnDevice)
            put("includeAddressPublicKey", state.includeAddressPublicKey)
            put("addressChunkify", state.addressChunkify)
            put("ethSignPathInput", state.ethSignPathInput)
            put("ethTo", state.ethTo)
            put("ethValue", state.ethValue)
            put("ethNonce", state.ethNonce)
            put("ethGasLimit", state.ethGasLimit)
            put("ethChainId", state.ethChainId)
            put("ethData", state.ethData)
            put("ethMaxFeePerGas", state.ethMaxFeePerGas)
            put("ethMaxPriorityFee", state.ethMaxPriorityFee)
            put("ethChunkify", state.ethChunkify)
            put("messageSignPathInput", state.messageSignPathInput)
            put("messagePayload", state.messagePayload)
            put("messageIsHex", state.messageIsHex)
            put("messageChunkify", state.messageChunkify)
            put("solSignPathInput", state.solSignPathInput)
            put("solSerializedTxHex", state.solSerializedTxHex)
            put("solChunkify", state.solChunkify)
            put("btcTxJsonInput", state.btcTxJsonInput)
            put("address", state.address)
            put("txSignResult", state.txSignResult)
            put("messageSignResult", state.messageSignResult)
            put("error", state.error)
            put("log", JSONArray(logEntries.toList()))
        }

    private fun restoreUiFromSnapshotJson(json: JSONObject) {
        val logs = json.optJSONArray("log") ?: JSONArray()
        val restoredLogs = ArrayDeque<String>(logs.length())
        for (i in 0 until logs.length()) {
            val value = logs.optString(i, "").trim()
            if (value.isNotEmpty()) {
                restoredLogs.addLast(value)
            }
        }

        val restoredChain = runCatching {
            Chain.valueOf(json.optString("selectedChain", Chain.ETHEREUM.name))
        }.getOrDefault(Chain.ETHEREUM)
        val restoredScreen = runCatching {
            AppScreen.valueOf(json.optString("screen", AppScreen.Home.name))
        }.getOrDefault(AppScreen.Home)

        suspendSnapshotWrites = true
        try {
            logEntries.clear()
            logEntries.addAll(restoredLogs)
            ui = UiState(
                screen = restoredScreen,
                status = json.optString("status", "Idle"),
                phaseSummary = json.optString("phaseSummary", "No session"),
                log = logEntries.toList(),
                selectedChain = restoredChain,
                addressPathInput = json.optString("addressPathInput", DEFAULT_ETH_PATH),
                showAddressOnDevice = json.optBoolean("showAddressOnDevice", true),
                includeAddressPublicKey = json.optBoolean("includeAddressPublicKey", false),
                addressChunkify = json.optBoolean("addressChunkify", false),
                ethSignPathInput = json.optString("ethSignPathInput", DEFAULT_ETH_PATH),
                ethTo = json.optString("ethTo", "0x000000000000000000000000000000000000dead"),
                ethValue = json.optString("ethValue", "0x0"),
                ethNonce = json.optString("ethNonce", "0x0"),
                ethGasLimit = json.optString("ethGasLimit", "0x5208"),
                ethChainId = json.optString("ethChainId", "1"),
                ethData = json.optString("ethData", "0x"),
                ethMaxFeePerGas = json.optString("ethMaxFeePerGas", "0x3b9aca00"),
                ethMaxPriorityFee = json.optString("ethMaxPriorityFee", "0x59682f00"),
                ethChunkify = json.optBoolean("ethChunkify", false),
                messageSignPathInput = json.optString("messageSignPathInput", DEFAULT_ETH_PATH),
                messagePayload = json.optString("messagePayload", "hello from hw-core"),
                messageIsHex = json.optBoolean("messageIsHex", false),
                messageChunkify = json.optBoolean("messageChunkify", false),
                solSignPathInput = json.optString("solSignPathInput", DEFAULT_SOL_PATH),
                solSerializedTxHex = json.optString("solSerializedTxHex", DEFAULT_SOLANA_TX_HEX),
                solChunkify = json.optBoolean("solChunkify", false),
                btcTxJsonInput = json.optString("btcTxJsonInput", DEFAULT_BITCOIN_TX_JSON.trim()),
                address = json.optString("address").takeIf { it.isNotBlank() },
                txSignResult = json.optString("txSignResult").takeIf { it.isNotBlank() },
                messageSignResult = json.optString("messageSignResult").takeIf { it.isNotBlank() },
                error = json.optString("error").takeIf { it.isNotBlank() },
                // Workflow/session handles cannot be restored across process/activity recreation.
                hasWorkflow = false,
                devices = emptyList(),
                selectedDeviceIndex = 0,
                sessionState = null,
                pairingPrompt = null,
                isBusy = false,
            )
        } finally {
            suspendSnapshotWrites = false
        }
    }

    private fun restoreUiFromJsonString(raw: String, source: String): Boolean =
        runCatching {
            restoreUiFromSnapshotJson(JSONObject(raw))
            true
        }.onFailure { err ->
            Log.w("HWCoreSample", "Failed to restore UI snapshot from $source: ${err.message}")
        }.getOrDefault(false)

    private fun persistUiSavedState() {
        if (suspendSnapshotWrites) return
        runCatching {
            savedStateHandle[UI_STATE_SAVED_KEY] = snapshotJson(ui).toString()
        }.onFailure { err ->
            Log.w("HWCoreSample", "Failed to persist UI saved state: ${err.message}")
        }
    }

    private fun persistUiSnapshot() {
        if (suspendSnapshotWrites) return
        val context = appContext ?: return

        runCatching {
            context.filesDir.resolve(UI_STATE_SNAPSHOT_FILE).writeText(snapshotJson(ui).toString())
        }.onFailure { err ->
            Log.w("HWCoreSample", "Failed to persist UI snapshot: ${err.message}")
        }
    }

    private fun restoreUiSnapshot() {
        val context = appContext ?: return
        val file = context.filesDir.resolve(UI_STATE_SNAPSHOT_FILE)
        if (!file.exists()) return
        restoreUiFromJsonString(file.readText(), "file")
    }

    private fun setError(msg: String) {
        log("ERROR: $msg")
        ui = ui.copy(error = msg, status = msg, isBusy = false)
    }

    fun onMissingBlePermissions() {
        setError("Bluetooth permissions are required before scanning.")
    }

    fun onBluetoothDisabled() {
        setError("Bluetooth is off. Turn it on and try again.")
    }

    private fun currentHostConfig(): HostConfig {
        val existing = hostConfig
        if (existing != null) {
            return existing
        }
        // Fallback for cases where initialize() hasn't run yet.
        val fallback = hostConfigNew("Android", DEFAULT_APP_NAME)
        hostConfig = fallback
        return fallback
    }

    private fun defaultHostName(context: Context): String {
        val settingsName = runCatching {
            Settings.Global.getString(context.contentResolver, "device_name")
        }.getOrNull()?.trim().orEmpty()
        if (settingsName.isNotEmpty()) {
            return settingsName
        }

        val model = Build.MODEL?.trim().orEmpty()
        if (model.isNotEmpty()) {
            return model
        }

        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        if (manufacturer.isNotEmpty()) {
            return manufacturer
        }

        return "Android"
    }

    private suspend fun <T> runWithTimeout(step: String, block: suspend () -> T): T {
        return try {
            withTimeout(SESSION_STEP_TIMEOUT_MS) { block() }
        } catch (_: TimeoutCancellationException) {
            throw IllegalStateException("$step timed out after ${SESSION_STEP_TIMEOUT_MS / 1000}s")
        }
    }

    private fun isStaleDeviceHandleError(error: Exception): Boolean =
        error.message.orEmpty().contains("device already connected", ignoreCase = true)

    private suspend fun dropWorkflow() {
        workflowEventsJob?.cancel()
        workflowEventsJob = null
        val wf = workflow
        if (wf != null) {
            runCatching { wf.abort() }.onFailure { err ->
                log("Abort warning: ${err.message}")
            }
            runCatching { wf.destroy() }
        }
        workflow = null
        pendingPairingFlow = null
    }

    private fun startWorkflowEventsPump(wf: BleWorkflowHandle) {
        workflowEventsJob?.cancel()
        workflowEventsJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive && workflow === wf) {
                try {
                    val event = wf.nextEvent(500uL) ?: continue
                    log("WF ${event.kind}/${event.code}: ${event.message}")
                } catch (e: Exception) {
                    if (workflow === wf) {
                        log("WF events stopped: ${e.message}")
                    }
                    break
                }
            }
        }
    }

    private suspend fun recoverAfterConnectFailure(errorMessage: String, requireRescan: Boolean) {
        dropWorkflow()
        ui = ui.copy(
            screen = AppScreen.Scanning,
            hasWorkflow = false,
            sessionState = null,
            pairingPrompt = null,
            phaseSummary = "No session",
            devices = if (requireRescan) emptyList() else ui.devices,
            selectedDeviceIndex = 0,
        )
        val suffix = if (requireRescan) " Tap Scan to refresh devices and reconnect." else ""
        setError("$errorMessage$suffix")
    }

    private fun selectedDevice(): BleDiscoveredDevice? = ui.devices.getOrNull(ui.selectedDeviceIndex)

    private fun chainDefaultPath(chain: Chain): String =
        chainConfig(chain).defaultPath

    private fun resolvedPath(input: String, chain: Chain): String {
        val trimmed = input.trim()
        return if (trimmed.isEmpty()) chainDefaultPath(chain) else trimmed
    }

    private fun parseUnsignedLong(value: String, fieldName: String): ULong {
        val trimmed = value.trim()
        require(trimmed.isNotEmpty()) { "$fieldName is required" }
        return if (trimmed.startsWith("0x", ignoreCase = true)) {
            trimmed.drop(2).toULong(16)
        } else {
            trimmed.toULong()
        }
    }

    private fun sanitizeHex(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.startsWith("0x", ignoreCase = true)) trimmed.drop(2) else trimmed
    }

    private fun describePhase(phase: SessionPhase): String =
        when (phase) {
            SessionPhase.NEEDS_CHANNEL -> "Needs channel"
            SessionPhase.NEEDS_HANDSHAKE -> "Needs handshake"
            SessionPhase.NEEDS_PAIRING_CODE -> "Needs pairing code"
            SessionPhase.NEEDS_CONNECTION_CONFIRMATION -> "Needs connection confirmation"
            SessionPhase.NEEDS_SESSION -> "Needs session"
            SessionPhase.READY -> "Ready"
        }

    private fun requiresPairingPrompt(phase: SessionPhase): Boolean =
        phase == SessionPhase.NEEDS_PAIRING_CODE ||
            phase == SessionPhase.NEEDS_CONNECTION_CONFIRMATION

    private fun applySessionState(state: SessionState) {
        val screen = when (state.phase) {
            SessionPhase.READY -> AppScreen.Ready
            SessionPhase.NEEDS_PAIRING_CODE,
            SessionPhase.NEEDS_CONNECTION_CONFIRMATION -> AppScreen.Pairing
            else -> AppScreen.Scanning
        }
        ui = ui.copy(
            sessionState = state,
            phaseSummary = describePhase(state.phase),
            status = when (state.phase) {
                SessionPhase.READY -> "Session ready"
                SessionPhase.NEEDS_SESSION -> "Paired. Run Connect to create session."
                SessionPhase.NEEDS_CONNECTION_CONFIRMATION -> "Waiting for device confirmation"
                SessionPhase.NEEDS_PAIRING_CODE -> "Pairing code required"
                SessionPhase.NEEDS_HANDSHAKE -> "Handshake required"
                SessionPhase.NEEDS_CHANNEL -> "Channel required"
            },
            hasWorkflow = true,
            screen = screen,
        )
        log("Session phase: ${ui.phaseSummary}")
    }

    private suspend fun ensureWorkflowFromSelectedDevice(): BleWorkflowHandle {
        workflow?.let { return it }

        val device = selectedDevice()
            ?: throw IllegalStateException("Select a scanned device first")
        val info = device.info()

        ui = ui.copy(screen = AppScreen.Connecting)
        log("Connecting to ${info.name ?: info.id}...")

        val session = device.connect()
        val wf = session.intoWorkflowWithStorage(currentHostConfig(), storagePath)
        workflow = wf
        startWorkflowEventsPump(wf)
        ui = ui.copy(hasWorkflow = true)
        log("BLE session connected")
        return wf
    }

    private suspend fun startPairing() {
        val wf = workflow ?: return setError("Pairing start failed: no active workflow")
        val prompt = wf.pairingStart()
        pendingPairingFlow = pendingPairingFlow ?: PendingPairingFlow.ConnectReady
        ui = ui.copy(
            screen = AppScreen.Pairing,
            pairingPrompt = prompt,
            isBusy = false,
            status = "Pairing required",
        )
        log("Pairing prompt: ${prompt.message}")
    }

    private suspend fun resumePendingFlowAfterPairing() {
        val wf = workflow ?: return setError("Session resume failed: no active workflow")
        when (pendingPairingFlow) {
            PendingPairingFlow.PairOnly -> {
                val state = runWithTimeout("Pair-only flow") {
                    wf.pairOnlyWithPolicy(true, retryPolicy)
                }
                applySessionState(state)
            }
            PendingPairingFlow.ConnectReady -> {
                val state = runWithTimeout("Connect-ready flow") {
                    wf.connectReadyWithPolicy(true, retryPolicy)
                }
                applySessionState(state)
            }
            null -> {
                val state = wf.sessionState()
                applySessionState(state)
            }
        }

        pendingPairingFlow = null

        if (ui.sessionState?.phase?.let(::requiresPairingPrompt) == true) {
            startPairing()
        } else {
            ui = ui.copy(pairingPrompt = null)
        }
    }

    // -- BLE Scan --

    fun scan() {
        ui = ui.copy(
            screen = AppScreen.Scanning,
            devices = emptyList(),
            selectedDeviceIndex = 0,
            sessionState = null,
            pairingPrompt = null,
            hasWorkflow = false,
            phaseSummary = "No session",
            status = "Scanning for devices...",
            error = null,
            isBusy = true,
        )
        log("Scanning for Trezor devices...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val adapter = BluetoothAdapter.getDefaultAdapter()
                if (adapter == null) {
                    return@launch setError("Scan failed: no Bluetooth adapter available on this device.")
                }
                if (!adapter.isEnabled) {
                    return@launch setError("Scan failed: Bluetooth is off. Turn it on and try again.")
                }
                if (bleManager == null) {
                    bleManager = BleManagerHandle.new()
                    log("BLE manager initialized")
                }
                val mgr = bleManager ?: return@launch setError("Scan failed: BLE manager unavailable")
                val found = mgr.discoverTrezor(5_000uL)

                dropWorkflow()

                log("Found ${found.size} device(s)")
                ui = ui.copy(
                    devices = found,
                    selectedDeviceIndex = 0,
                    sessionState = null,
                    hasWorkflow = false,
                    pairingPrompt = null,
                    phaseSummary = "No session",
                    status = "Found ${found.size} device(s)",
                    isBusy = false,
                )
            } catch (e: Exception) {
                setError("Scan failed: ${e.message}")
            }
        }
    }

    fun selectDeviceIndex(index: Int) {
        if (index !in ui.devices.indices) {
            return
        }
        val info = ui.devices[index].info()
        ui = ui.copy(selectedDeviceIndex = index)
        log("Selected device: ${info.name ?: info.id}")
    }

    // -- Session actions --

    fun pairOnly() {
        ui = ui.copy(isBusy = true, error = null)
        log("Pair-only flow requested...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = ensureWorkflowFromSelectedDevice()
                pendingPairingFlow = PendingPairingFlow.PairOnly
                log("Advancing workflow to paired state...")
                val state = runWithTimeout("Pair-only flow") {
                    wf.pairOnlyWithPolicy(true, retryPolicy)
                }
                applySessionState(state)
                if (requiresPairingPrompt(state.phase)) {
                    startPairing()
                } else {
                    ui = ui.copy(pairingPrompt = null, isBusy = false)
                }
            } catch (e: Exception) {
                dropWorkflow()
                setError("Pair only failed: ${e.message}")
            }
        }
    }

    fun connectReady() {
        ui = ui.copy(isBusy = true, error = null)
        log("Connect-ready flow requested...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = ensureWorkflowFromSelectedDevice()
                pendingPairingFlow = PendingPairingFlow.ConnectReady
                log("Advancing workflow to session-ready state...")
                val state = runWithTimeout("Connect-ready flow") {
                    wf.connectReadyWithPolicy(true, retryPolicy)
                }
                applySessionState(state)
                if (requiresPairingPrompt(state.phase)) {
                    startPairing()
                } else {
                    ui = ui.copy(pairingPrompt = null, isBusy = false)
                }
            } catch (e: Exception) {
                if (isStaleDeviceHandleError(e)) {
                    recoverAfterConnectFailure(
                        "Connect failed: selected device handle is stale.",
                        requireRescan = true,
                    )
                } else {
                    recoverAfterConnectFailure(
                        "Connect failed: ${e.message}",
                        requireRescan = false,
                    )
                }
            }
        }
    }

    // -- Pairing --

    fun submitPairingCode(code: String) {
        val trimmed = code.trim()
        if (trimmed.length != 6 || trimmed.any { !it.isDigit() }) {
            setError("Pairing code must be 6 digits")
            return
        }

        log("Submitting pairing code...")
        ui = ui.copy(isBusy = true, error = null)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch setError("Pairing failed: no active workflow")
                val progress = wf.pairingSubmitCode(trimmed)
                log("Pairing progress: ${progress.kind} - ${progress.message}")

                when (progress.kind) {
                    PairingProgressKind.AWAITING_CONNECTION_CONFIRMATION -> {
                        ui = ui.copy(isBusy = false)
                    }
                    PairingProgressKind.COMPLETED -> {
                        resumePendingFlowAfterPairing()
                        ui = ui.copy(isBusy = false)
                    }
                    PairingProgressKind.AWAITING_CODE -> {
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
                val wf = workflow ?: return@launch setError("Confirm failed: no active workflow")
                val progress = wf.pairingConfirmConnection()
                log("Confirm progress: ${progress.kind} - ${progress.message}")
                if (progress.kind == PairingProgressKind.COMPLETED) {
                    resumePendingFlowAfterPairing()
                }
                ui = ui.copy(isBusy = false)
            } catch (e: Exception) {
                setError("Confirm failed: ${e.message}")
            }
        }
    }

    // -- Chain & input controls --

    fun selectChain(chain: Chain) {
        val nextAddressPath = chainDefaultPath(chain)
        val nextMessagePath = if (chain == Chain.SOLANA) ui.messageSignPathInput else chainDefaultPath(chain)
        ui = ui.copy(
            selectedChain = chain,
            addressPathInput = nextAddressPath,
            messageSignPathInput = nextMessagePath,
            address = null,
            txSignResult = null,
            messageSignResult = null,
            error = null,
        )
        log("Selected chain: ${chainLabel(chain)}")
    }

    fun updateAddressPathInput(value: String) { ui = ui.copy(addressPathInput = value) }
    fun setShowAddressOnDevice(value: Boolean) { ui = ui.copy(showAddressOnDevice = value) }
    fun setIncludeAddressPublicKey(value: Boolean) { ui = ui.copy(includeAddressPublicKey = value) }
    fun setAddressChunkify(value: Boolean) { ui = ui.copy(addressChunkify = value) }

    fun updateEthSignPathInput(value: String) { ui = ui.copy(ethSignPathInput = value) }
    fun updateEthTo(value: String) { ui = ui.copy(ethTo = value) }
    fun updateEthValue(value: String) { ui = ui.copy(ethValue = value) }
    fun updateEthNonce(value: String) { ui = ui.copy(ethNonce = value) }
    fun updateEthGasLimit(value: String) { ui = ui.copy(ethGasLimit = value) }
    fun updateEthChainId(value: String) { ui = ui.copy(ethChainId = value) }
    fun updateEthData(value: String) { ui = ui.copy(ethData = value) }
    fun updateEthMaxFeePerGas(value: String) { ui = ui.copy(ethMaxFeePerGas = value) }
    fun updateEthMaxPriorityFee(value: String) { ui = ui.copy(ethMaxPriorityFee = value) }
    fun setEthChunkify(value: Boolean) { ui = ui.copy(ethChunkify = value) }

    fun updateMessageSignPathInput(value: String) { ui = ui.copy(messageSignPathInput = value) }
    fun updateMessagePayload(value: String) { ui = ui.copy(messagePayload = value) }
    fun setMessageHexMode(value: Boolean) { ui = ui.copy(messageIsHex = value) }
    fun setMessageChunkify(value: Boolean) { ui = ui.copy(messageChunkify = value) }

    fun updateSolSignPathInput(value: String) { ui = ui.copy(solSignPathInput = value) }
    fun updateSolSerializedTxHex(value: String) { ui = ui.copy(solSerializedTxHex = value) }
    fun setSolChunkify(value: Boolean) { ui = ui.copy(solChunkify = value) }

    fun updateBitcoinTxJson(value: String) { ui = ui.copy(btcTxJsonInput = value) }

    fun signPreview(): String {
        val state = ui
        return when (state.selectedChain) {
            Chain.ETHEREUM -> {
                "ETH path=${resolvedPath(state.ethSignPathInput, Chain.ETHEREUM)} to=${state.ethTo.trim()} " +
                    "value=${state.ethValue.trim()} nonce=${state.ethNonce.trim()} " +
                    "gas_limit=${state.ethGasLimit.trim()} chain_id=${state.ethChainId.trim()}"
            }
            Chain.SOLANA -> {
                val bytes = sanitizeHex(state.solSerializedTxHex).length / 2
                "SOL path=${resolvedPath(state.solSignPathInput, Chain.SOLANA)} tx_hex_bytes=$bytes"
            }
            Chain.BITCOIN -> {
                summarizeBitcoinTxJson(state.btcTxJsonInput)
                    ?.let { "BTC $it" }
                    ?: "BTC invalid tx JSON"
            }
        }
    }

    fun messageSignPreview(): String {
        val state = ui
        return when (state.selectedChain) {
            Chain.ETHEREUM -> {
                "ETH path=${resolvedPath(state.messageSignPathInput, Chain.ETHEREUM)} " +
                    "hex=${state.messageIsHex} bytes=${state.messagePayload.toByteArray().size}"
            }
            Chain.BITCOIN -> {
                "BTC path=${resolvedPath(state.messageSignPathInput, Chain.BITCOIN)} " +
                    "hex=${state.messageIsHex} bytes=${state.messagePayload.toByteArray().size}"
            }
            Chain.SOLANA -> "SOL message signing not supported"
        }
    }

    // -- Requests --

    fun getAddress() {
        ui = ui.copy(address = null, error = null, isBusy = true)
        log("Getting ${chainLabel(ui.selectedChain)} address...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch setError("Get address failed: connect first")
                if (ui.sessionState?.canGetAddress != true) {
                    return@launch setError("Get address failed: session is not ready")
                }

                val chain = ui.selectedChain
                val request = GetAddressRequest(
                    chain = chain,
                    path = resolvedPath(ui.addressPathInput, chain),
                    showOnDevice = ui.showAddressOnDevice,
                    includePublicKey = ui.includeAddressPublicKey,
                    chunkify = ui.addressChunkify,
                )
                val result = wf.getAddress(request)
                ui = ui.copy(address = result.address, isBusy = false, status = "Address received")
                log("${chainLabel(chain)} address: ${result.address}")
            } catch (e: Exception) {
                setError("Get address failed: ${e.message}")
            }
        }
    }

    fun signTx() {
        ui = ui.copy(txSignResult = null, error = null, isBusy = true)
        val chain = ui.selectedChain
        log("Signing ${chainLabel(chain)} transaction...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch setError("Sign tx failed: connect first")
                if (ui.sessionState?.canSignTx != true) {
                    return@launch setError("Sign tx failed: session is not ready")
                }

                val request = buildSignTxRequest()
                val result = wf.signTx(request)
                val display = formatSignTxResult(chain, result)
                ui = ui.copy(txSignResult = display, isBusy = false, status = "Transaction signed")
                log("${chainLabel(chain)} sign result ready")
            } catch (e: Exception) {
                setError("Sign tx failed: ${e.message}")
            }
        }
    }

    fun signMessage() {
        val chain = ui.selectedChain
        if (chain == Chain.SOLANA) {
            setError("Message signing supports ETH/BTC only")
            return
        }

        ui = ui.copy(messageSignResult = null, error = null, isBusy = true)
        log("Signing ${chainLabel(chain)} message...")

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val wf = workflow ?: return@launch setError("Sign message failed: connect first")
                if (ui.sessionState?.canSignTx != true) {
                    return@launch setError("Sign message failed: session is not ready")
                }

                val request = SignMessageRequest(
                    chain = chain,
                    path = resolvedPath(ui.messageSignPathInput, chain),
                    message = ui.messagePayload.trim(),
                    isHex = ui.messageIsHex,
                    chunkify = ui.messageChunkify,
                )
                val result = wf.signMessage(request)
                val display = buildString {
                    appendLine("address = ${result.address}")
                    appendLine("encoding = ${result.signatureEncoding}")
                    appendLine("signature = ${result.signatureFormatted}")
                }.trimEnd()

                ui = ui.copy(
                    messageSignResult = display,
                    isBusy = false,
                    status = "Message signed",
                )
                log("${chainLabel(chain)} message sign result ready")
            } catch (e: Exception) {
                setError("Sign message failed: ${e.message}")
            }
        }
    }

    private fun buildSignTxRequest(): SignTxRequest {
        val state = ui
        return when (state.selectedChain) {
            Chain.ETHEREUM -> {
                val chainId = parseUnsignedLong(state.ethChainId, "ETH chain id")
                SignTxRequest(
                    chain = Chain.ETHEREUM,
                    path = resolvedPath(state.ethSignPathInput, Chain.ETHEREUM),
                    to = state.ethTo.trim(),
                    value = state.ethValue.trim().ifEmpty { "0x0" },
                    nonce = state.ethNonce.trim().ifEmpty { "0x0" },
                    gasLimit = state.ethGasLimit.trim(),
                    chainId = chainId,
                    data = state.ethData.trim().ifEmpty { "0x" },
                    maxFeePerGas = state.ethMaxFeePerGas.trim(),
                    maxPriorityFee = state.ethMaxPriorityFee.trim(),
                    accessList = emptyList(),
                    chunkify = state.ethChunkify,
                )
            }

            Chain.BITCOIN -> {
                val json = state.btcTxJsonInput.trim()
                require(json.isNotEmpty()) { "BTC tx JSON is required" }
                JSONObject(json)
                SignTxRequest(
                    chain = Chain.BITCOIN,
                    path = "",
                    to = "",
                    value = "",
                    nonce = "",
                    gasLimit = "",
                    chainId = 0uL,
                    data = json,
                    maxFeePerGas = "",
                    maxPriorityFee = "",
                    accessList = emptyList(),
                    chunkify = false,
                )
            }

            Chain.SOLANA -> {
                val serialized = sanitizeHex(state.solSerializedTxHex)
                require(serialized.isNotEmpty()) { "SOL serialized tx hex is required" }
                SignTxRequest(
                    chain = Chain.SOLANA,
                    path = resolvedPath(state.solSignPathInput, Chain.SOLANA),
                    to = "",
                    value = "",
                    nonce = "",
                    gasLimit = "",
                    chainId = 0uL,
                    data = serialized,
                    maxFeePerGas = "",
                    maxPriorityFee = "",
                    accessList = emptyList(),
                    chunkify = state.solChunkify,
                )
            }
        }
    }

    private fun formatSignTxResult(chain: Chain, result: SignTxResult): String = buildString {
        when (chain) {
            Chain.ETHEREUM -> {
                appendLine("v = ${result.v}")
                appendLine("r = ${result.r.toHex()}")
                appendLine("s = ${result.s.toHex()}")
                result.txHash?.let { appendLine("tx_hash = ${it.toHex()}") }
                result.recoveredAddress?.let { appendLine("from = $it") }
            }

            Chain.BITCOIN,
            Chain.SOLANA -> {
                appendLine("signature = ${result.r.toHex()}")
            }
        }
    }.trimEnd()

    private fun summarizeBitcoinTxJson(json: String): String? {
        return try {
            val obj = JSONObject(json)
            val inputs = obj.optJSONArray("inputs")?.length() ?: 0
            val outputs = obj.optJSONArray("outputs")?.length() ?: 0
            val refTxs = obj.optJSONArray("ref_txs")?.length() ?: 0
            "inputs=$inputs outputs=$outputs ref_txs=$refTxs"
        } catch (_: Exception) {
            null
        }
    }

    fun chainLabel(chain: Chain): String =
        when (chain) {
            Chain.ETHEREUM -> "ETH"
            Chain.BITCOIN -> "BTC"
            Chain.SOLANA -> "SOL"
        }

    fun disconnect() {
        viewModelScope.launch(Dispatchers.IO) {
            dropWorkflow()
            ui = ui.copy(
                screen = AppScreen.Scanning,
                devices = emptyList(),
                selectedDeviceIndex = 0,
                sessionState = null,
                hasWorkflow = false,
                phaseSummary = "No session",
                pairingPrompt = null,
                address = null,
                txSignResult = null,
                messageSignResult = null,
                isBusy = false,
                status = "Disconnected. Tap Scan to reconnect.",
            )
            log("Disconnected session; scan required for reconnect")
        }
    }

    // -- Cleanup --

    fun reset() {
        viewModelScope.launch(Dispatchers.IO) {
            dropWorkflow()
            logEntries.clear()
            ui = UiState()
        }
    }

    override fun onCleared() {
        workflowEventsJob?.cancel()
        workflow?.destroy()
        bleManager?.destroy()
        super.onCleared()
    }
}

private val HEX_CHARS = "0123456789abcdef".toCharArray()

/** O(N) hex encoding without String.format overhead. */
private fun ByteArray.toHex(): String = buildString(size * 2) {
    for (b in this@toHex) {
        val i = b.toInt() and 0xff
        append(HEX_CHARS[i shr 4])
        append(HEX_CHARS[i and 0xf])
    }
}
