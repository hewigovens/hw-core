package dev.hewig.hwcore

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import dev.hewig.hwcore.ui.theme.HWCoreTheme
import uniffi.hwcore.*

class MainActivity : ComponentActivity() {

    init {
        // Ensures JNI_OnLoad in libhwcore runs on Android before BLE calls.
        System.loadLibrary("hwcore")
    }

    private val blePermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    } else {
        arrayOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ ->
            hasBlePermissions = hasAllBlePermissions()
            isBluetoothEnabled = isBluetoothOn()
        }
    private val vm: MainViewModel by viewModels()

    private var hasBlePermissions by mutableStateOf(false)
    private var isBluetoothEnabled by mutableStateOf(false)
    private var hasRequestedBlePermissions by mutableStateOf(false)

    private fun hasAllBlePermissions(): Boolean =
        blePermissions.all {
            ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }

    private fun isBluetoothOn(): Boolean =
        try {
            BluetoothAdapter.getDefaultAdapter()?.isEnabled == true
        } catch (_: SecurityException) {
            false
        }

    private fun openAppSettings() {
        val intent = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.fromParts("package", packageName, null),
        )
        startActivity(intent)
    }

    private fun openBluetoothSettings() {
        startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
    }

    private fun requestBlePermissionsOrSettings() {
        val missing = blePermissions.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            hasBlePermissions = true
            return
        }

        val permanentlyDenied = hasRequestedBlePermissions &&
            missing.any { permission ->
                !ActivityCompat.shouldShowRequestPermissionRationale(this, permission)
            }
        if (permanentlyDenied) {
            Toast.makeText(
                this,
                "Bluetooth permissions are denied. Enable them in App Settings.",
                Toast.LENGTH_LONG,
            ).show()
            openAppSettings()
            return
        }

        hasRequestedBlePermissions = true
        permissionLauncher.launch(missing.toTypedArray())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vm.initialize(applicationContext)

        hasBlePermissions = hasAllBlePermissions()
        isBluetoothEnabled = isBluetoothOn()
        if (!hasBlePermissions) {
            requestBlePermissionsOrSettings()
        }

        setContent {
            HWCoreTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    MainScreen(
                        hasBlePermissions = hasBlePermissions,
                        isBluetoothEnabled = isBluetoothEnabled,
                        onRequestBlePermissions = { requestBlePermissionsOrSettings() },
                        onOpenBluetoothSettings = { openBluetoothSettings() },
                        vm = vm,
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        hasBlePermissions = hasAllBlePermissions()
        isBluetoothEnabled = isBluetoothOn()
    }
}

@Composable
fun MainScreen(
    hasBlePermissions: Boolean,
    isBluetoothEnabled: Boolean,
    onRequestBlePermissions: () -> Unit,
    onOpenBluetoothSettings: () -> Unit,
    vm: MainViewModel,
) {
    val ui = vm.ui
    val clipboard = LocalClipboardManager.current
    var selectedTab by rememberSaveable { mutableStateOf(0) } // 0 = Main, 1 = Config, 2 = Logs
    val showMainTab = selectedTab == 0
    val showConfigTab = selectedTab == 1
    val showLogsTab = selectedTab == 2

    val canPairOnly = !ui.isBusy && (ui.sessionState?.canPairOnly == true || (!ui.hasWorkflow && ui.devices.isNotEmpty()))
    val canConnect = !ui.isBusy && (ui.sessionState?.canConnect == true || (!ui.hasWorkflow && ui.devices.isNotEmpty()))
    val canGetAddress = !ui.isBusy && ui.sessionState?.canGetAddress == true
    val canSign = !ui.isBusy && ui.sessionState?.canSignTx == true
    val canSignMessage = canSign && ui.selectedChain != Chain.SOLANA
    val canDisconnect = !ui.isBusy && ui.hasWorkflow

    fun requireBluetooth(action: () -> Unit) {
        if (!hasBlePermissions) {
            vm.onMissingBlePermissions()
            onRequestBlePermissions()
            return
        }
        if (!isBluetoothEnabled) {
            vm.onBluetoothDisabled()
            onOpenBluetoothSettings()
            return
        }
        action()
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(
                text = "HW Core Sample",
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = "hw-core ${hwCoreVersion()}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (!hasBlePermissions) {
            item {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Bluetooth permissions required", style = MaterialTheme.typography.labelLarge)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            "Grant Nearby Devices/Bluetooth permissions to scan for hardware wallets.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(onClick = onRequestBlePermissions) {
                            Text("Grant Permissions")
                        }
                    }
                }
            }
        }

        if (hasBlePermissions && !isBluetoothEnabled) {
            item {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Bluetooth is off", style = MaterialTheme.typography.labelLarge)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            "Turn on Bluetooth to scan/connect.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(onClick = onOpenBluetoothSettings) {
                            Text("Open Bluetooth Settings")
                        }
                    }
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = ui.status, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        text = "Session phase: ${ui.phaseSummary}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (ui.isBusy) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
            }
        }

        item {
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Main") },
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Config") },
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("Logs") },
                )
            }
        }

        if (showMainTab) {
            if (ui.devices.isNotEmpty()) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Device", style = MaterialTheme.typography.titleMedium)
                            ui.devices.forEachIndexed { index, device ->
                                val info = device.info()
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { vm.selectDeviceIndex(index) }
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    RadioButton(
                                        selected = index == ui.selectedDeviceIndex,
                                        onClick = { vm.selectDeviceIndex(index) },
                                    )
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(info.name ?: "Unknown Device")
                                        Text(
                                            text = info.id,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            fontFamily = FontFamily.Monospace,
                                        )
                                        info.rssi?.let {
                                            Text(
                                                text = "RSSI: $it",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Actions", style = MaterialTheme.typography.titleMedium)

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Button(
                                onClick = { requireBluetooth { vm.scan() } },
                                enabled = !ui.isBusy,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Scan")
                            }
                            Button(
                                onClick = { requireBluetooth { vm.pairOnly() } },
                                enabled = canPairOnly,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Pair Only")
                            }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Button(
                                onClick = { requireBluetooth { vm.connectReady() } },
                                enabled = canConnect,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Connect")
                            }
                            Button(
                                onClick = { vm.getAddress() },
                                enabled = canGetAddress,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Address")
                            }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Button(
                                onClick = { vm.signTx() },
                                enabled = canSign,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Sign")
                            }
                            Button(
                                onClick = { vm.signMessage() },
                                enabled = canSignMessage,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Sign Msg")
                            }
                        }

                        OutlinedButton(
                            onClick = { vm.disconnect() },
                            enabled = canDisconnect,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Disconnect")
                        }

                        OutlinedButton(
                            onClick = { vm.reset() },
                            enabled = !ui.isBusy,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Reset")
                        }
                    }
                }
            }

        if (ui.pairingPrompt != null) {
            item {
                var code by rememberSaveable { mutableStateOf("") }
                val prompt = ui.pairingPrompt
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Pairing", style = MaterialTheme.typography.titleMedium)
                        Text(prompt?.message.orEmpty(), style = MaterialTheme.typography.bodyMedium)

                        OutlinedTextField(
                            value = code,
                            onValueChange = { value ->
                                if (value.length <= 6) {
                                    code = value.filter { it.isDigit() }
                                }
                            },
                            label = { Text("Pairing Code") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.isBusy,
                        )

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { vm.submitPairingCode(code) },
                                enabled = !ui.isBusy && code.length == 6,
                            ) {
                                Text("Submit Code")
                            }

                            if (prompt?.requiresConnectionConfirmation == true) {
                                OutlinedButton(
                                    onClick = { vm.confirmConnection() },
                                    enabled = !ui.isBusy,
                                ) {
                                    Text("Confirm on Device")
                                }
                            }
                        }
                    }
                }
            }
        }
        }

        if (showConfigTab) {
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Chain", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Chain.values().forEach { chain ->
                            FilterChip(
                                selected = chain == ui.selectedChain,
                                onClick = { vm.selectChain(chain) },
                                label = { Text(vm.chainLabel(chain)) },
                                enabled = !ui.isBusy,
                            )
                        }
                    }
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Address Request", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = ui.addressPathInput,
                        onValueChange = vm::updateAddressPathInput,
                        label = { Text("Path (empty uses chain default)") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !ui.isBusy,
                    )
                    ToggleRow(
                        title = "Show on device",
                        checked = ui.showAddressOnDevice,
                        onCheckedChange = vm::setShowAddressOnDevice,
                        enabled = !ui.isBusy,
                    )
                    ToggleRow(
                        title = "Include public key",
                        checked = ui.includeAddressPublicKey,
                        onCheckedChange = vm::setIncludeAddressPublicKey,
                        enabled = !ui.isBusy,
                    )
                    ToggleRow(
                        title = "Chunkify",
                        checked = ui.addressChunkify,
                        onCheckedChange = vm::setAddressChunkify,
                        enabled = !ui.isBusy,
                    )
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Sign Request", style = MaterialTheme.typography.titleMedium)

                    when (ui.selectedChain) {
                        Chain.ETHEREUM -> {
                            OutlinedTextField(
                                value = ui.ethSignPathInput,
                                onValueChange = vm::updateEthSignPathInput,
                                label = { Text("Path (ETH)") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethTo,
                                onValueChange = vm::updateEthTo,
                                label = { Text("To") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethValue,
                                onValueChange = vm::updateEthValue,
                                label = { Text("Value") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethNonce,
                                onValueChange = vm::updateEthNonce,
                                label = { Text("Nonce") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethChainId,
                                onValueChange = vm::updateEthChainId,
                                label = { Text("Chain ID") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethGasLimit,
                                onValueChange = vm::updateEthGasLimit,
                                label = { Text("Gas Limit") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethMaxFeePerGas,
                                onValueChange = vm::updateEthMaxFeePerGas,
                                label = { Text("Max Fee") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethMaxPriorityFee,
                                onValueChange = vm::updateEthMaxPriorityFee,
                                label = { Text("Priority Fee") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.ethData,
                                onValueChange = vm::updateEthData,
                                label = { Text("Data") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            ToggleRow(
                                title = "Chunkify",
                                checked = ui.ethChunkify,
                                onCheckedChange = vm::setEthChunkify,
                                enabled = !ui.isBusy,
                            )
                        }

                        Chain.BITCOIN -> {
                            OutlinedTextField(
                                value = ui.btcTxJsonInput,
                                onValueChange = vm::updateBitcoinTxJson,
                                label = { Text("Transaction JSON") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(220.dp),
                                enabled = !ui.isBusy,
                                maxLines = 12,
                                minLines = 8,
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            )
                            Text(
                                text = "BTC signing requires ref_txs that match each input prev_hash/prev_index.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }

                        Chain.SOLANA -> {
                            OutlinedTextField(
                                value = ui.solSignPathInput,
                                onValueChange = vm::updateSolSignPathInput,
                                label = { Text("Path (SOL)") },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !ui.isBusy,
                            )
                            OutlinedTextField(
                                value = ui.solSerializedTxHex,
                                onValueChange = vm::updateSolSerializedTxHex,
                                label = { Text("Serialized Tx Hex") },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(180.dp),
                                enabled = !ui.isBusy,
                                maxLines = 8,
                                minLines = 4,
                                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            )
                            ToggleRow(
                                title = "Chunkify",
                                checked = ui.solChunkify,
                                onCheckedChange = vm::setSolChunkify,
                                enabled = !ui.isBusy,
                            )
                        }
                    }

                    Divider(modifier = Modifier.padding(vertical = 4.dp))

                    if (ui.selectedChain == Chain.ETHEREUM || ui.selectedChain == Chain.BITCOIN) {
                        Text("Message Sign", style = MaterialTheme.typography.titleSmall)
                        OutlinedTextField(
                            value = ui.messageSignPathInput,
                            onValueChange = vm::updateMessageSignPathInput,
                            label = { Text("Path (${vm.chainLabel(ui.selectedChain)})") },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.isBusy,
                        )
                        OutlinedTextField(
                            value = ui.messagePayload,
                            onValueChange = vm::updateMessagePayload,
                            label = { Text("Message") },
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.isBusy,
                        )
                        ToggleRow(
                            title = "Message is hex",
                            checked = ui.messageIsHex,
                            onCheckedChange = vm::setMessageHexMode,
                            enabled = !ui.isBusy,
                        )
                        ToggleRow(
                            title = "Chunkify",
                            checked = ui.messageChunkify,
                            onCheckedChange = vm::setMessageChunkify,
                            enabled = !ui.isBusy,
                        )
                    } else {
                        Text(
                            "Message signing is available for ETH/BTC only.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    Divider(modifier = Modifier.padding(vertical = 4.dp))

                    Text("Preview", style = MaterialTheme.typography.titleSmall)
                    Text(
                        vm.signPreview(),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    if (ui.selectedChain != Chain.SOLANA) {
                        Text(
                            vm.messageSignPreview(),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
        }

        if (showMainTab && (ui.address != null || ui.txSignResult != null || ui.messageSignResult != null)) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Results", style = MaterialTheme.typography.titleMedium)

                        ui.address?.let { address ->
                            Text("Address", style = MaterialTheme.typography.labelMedium)
                            Text(
                                address,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp,
                            )
                            OutlinedButton(onClick = {
                                clipboard.setText(AnnotatedString(address))
                            }) {
                                Text("Copy Address")
                            }
                        }

                        ui.txSignResult?.let { signature ->
                            Divider()
                            Text("Tx Signature", style = MaterialTheme.typography.labelMedium)
                            Text(
                                signature,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                            )
                            OutlinedButton(onClick = {
                                clipboard.setText(AnnotatedString(signature))
                            }) {
                                Text("Copy Tx Signature")
                            }
                        }

                        ui.messageSignResult?.let { signature ->
                            Divider()
                            Text("Message Signature", style = MaterialTheme.typography.labelMedium)
                            Text(
                                signature,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                            )
                            OutlinedButton(onClick = {
                                clipboard.setText(AnnotatedString(signature))
                            }) {
                                Text("Copy Message Signature")
                            }
                        }
                    }
                }
            }
        }

        ui.error?.let { error ->
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = error,
                        modifier = Modifier.padding(12.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        fontSize = 13.sp,
                    )
                }
            }
        }

        if (showLogsTab) {
            item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Logs", style = MaterialTheme.typography.titleMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { vm.clearLogs() }) {
                                Text("Clear")
                            }
                            OutlinedButton(onClick = {
                                clipboard.setText(AnnotatedString(ui.log.joinToString("\n")))
                            }) {
                                Text("Copy")
                            }
                        }
                    }

                    val logPreview = ui.log.takeLast(200).joinToString("\n").ifEmpty { "No logs yet." }
                    Text(
                        text = logPreview,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                    )
                }
            }
        }
        }
    }

    LaunchedEffect(ui.log.size) {
        // keep composition responsive when logs append quickly
    }
}

@Composable
private fun ToggleRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title)
        Spacer(modifier = Modifier.width(12.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
        )
    }
}
