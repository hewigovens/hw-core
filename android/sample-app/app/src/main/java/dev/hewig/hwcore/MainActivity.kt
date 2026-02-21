package dev.hewig.hwcore

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.hewig.hwcore.ui.theme.HWCoreTheme
import uniffi.hwcore.hwCoreVersion

class MainActivity : ComponentActivity() {

    init {
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
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request BLE permissions if not granted
        val missing = blePermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
        }

        setContent {
            HWCoreTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    MainScreen()
                }
            }
        }
    }
}

@Composable
fun MainScreen(vm: MainViewModel = viewModel()) {
    val ui = vm.ui

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        // Header
        Text(
            text = "HW Core Sample",
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            text = "hw-core ${hwCoreVersion()}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Main content area
        when (ui.screen) {
            AppScreen.Home -> HomeContent(onScan = { vm.scan() })

            AppScreen.Scanning -> ScanContent(
                devices = ui.devices,
                isBusy = ui.isBusy,
                onScan = { vm.scan() },
                onSelect = { vm.connectDevice(it) },
            )

            AppScreen.Connecting -> {
                Column {
                    Text("Connecting...")
                    if (ui.isBusy) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    }
                }
            }

            AppScreen.Pairing -> PairingContent(
                prompt = ui.pairingPrompt,
                isBusy = ui.isBusy,
                onSubmitCode = { vm.submitPairingCode(it) },
                onConfirm = { vm.confirmConnection() },
            )

            AppScreen.Ready -> ReadyContent(
                address = ui.address,
                signResult = ui.signResult,
                isBusy = ui.isBusy,
                onGetAddress = { vm.getEthAddress() },
                onSignTx = { vm.signEthTx() },
            )
        }

        // Error display
        ui.error?.let { error ->
            Spacer(modifier = Modifier.height(8.dp))
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                ),
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

        Spacer(modifier = Modifier.height(8.dp))

        // Reset button (always visible except on Home)
        if (ui.screen != AppScreen.Home) {
            OutlinedButton(onClick = { vm.reset() }) {
                Text("Reset")
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        // Log panel
        Text(
            text = "Log",
            style = MaterialTheme.typography.titleSmall,
        )
        Spacer(modifier = Modifier.height(4.dp))

        val listState = rememberLazyListState()
        LaunchedEffect(ui.log.size) {
            if (ui.log.isNotEmpty()) {
                listState.animateScrollToItem(ui.log.size - 1)
            }
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier.padding(8.dp),
            ) {
                items(ui.log) { line ->
                    Text(
                        text = line,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        lineHeight = 15.sp,
                    )
                }
            }
        }
    }
}

@Composable
fun HomeContent(onScan: () -> Unit) {
    Column {
        Text(
            text = "Connect your Trezor Safe 7 via Bluetooth to get started.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onScan) {
            Text("Scan for Devices")
        }
    }
}

@Composable
fun ScanContent(
    devices: List<uniffi.hwcore.BleDiscoveredDevice>,
    isBusy: Boolean,
    onScan: () -> Unit,
    onSelect: (uniffi.hwcore.BleDiscoveredDevice) -> Unit,
) {
    Column {
        if (isBusy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Spacer(modifier = Modifier.height(8.dp))
            Text("Scanning...")
        } else {
            Button(onClick = onScan) {
                Text("Scan Again")
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (devices.isEmpty() && !isBusy) {
            Text("No devices found. Make sure your Trezor is on and in range.")
        }

        devices.forEach { device ->
            val info = device.info()
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = info.name ?: "Unknown Device",
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Text(
                            text = info.id,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        info.rssi?.let {
                            Text(
                                text = "RSSI: $it",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    Button(onClick = { onSelect(device) }) {
                        Text("Connect")
                    }
                }
            }
        }
    }
}

@Composable
fun PairingContent(
    prompt: uniffi.hwcore.PairingPrompt?,
    isBusy: Boolean,
    onSubmitCode: (String) -> Unit,
    onConfirm: () -> Unit,
) {
    var code by remember { mutableStateOf("") }

    Column {
        Text(
            text = "Pairing Required",
            style = MaterialTheme.typography.titleMedium,
        )

        prompt?.let {
            Text(
                text = it.message,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 8.dp),
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedTextField(
            value = code,
            onValueChange = { if (it.length <= 6) code = it },
            label = { Text("Pairing Code") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(modifier = Modifier.height(12.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { onSubmitCode(code) },
                enabled = code.isNotEmpty() && !isBusy,
            ) {
                Text("Submit Code")
            }

            if (prompt?.requiresConnectionConfirmation == true) {
                OutlinedButton(
                    onClick = onConfirm,
                    enabled = !isBusy,
                ) {
                    Text("Confirm on Device")
                }
            }
        }

        if (isBusy) {
            Spacer(modifier = Modifier.height(8.dp))
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
fun ReadyContent(
    address: String?,
    signResult: String?,
    isBusy: Boolean,
    onGetAddress: () -> Unit,
    onSignTx: () -> Unit,
) {
    Column {
        Text(
            text = "Session Ready",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary,
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Get Address
        Button(
            onClick = onGetAddress,
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Get ETH Address")
        }

        address?.let {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("ETH Address:", style = MaterialTheme.typography.labelMedium)
                    Text(
                        text = it,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Sign Transaction
        Button(
            onClick = onSignTx,
            enabled = !isBusy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Sign ETH Tx (0 ETH to 0xdead)")
        }

        signResult?.let {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Signature:", style = MaterialTheme.typography.labelMedium)
                    Text(
                        text = it,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                    )
                }
            }
        }

        if (isBusy) {
            Spacer(modifier = Modifier.height(8.dp))
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }
    }
}
