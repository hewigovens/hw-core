import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = ContentViewModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        platformContent
        .task {
            await viewModel.bootstrap()
        }
        .onChange(of: viewModel.selectedChain) { _ in
            viewModel.selectedChainDidChange()
        }
        .onChange(of: scenePhase) { newPhase in
            Task { await viewModel.scenePhaseDidChange(newPhase) }
        }
        .alert("Pairing Code", isPresented: $viewModel.showPairingAlert) {
            TextField("123456", text: $viewModel.pairingCodeInput)
                .accessibilityLabel("Pairing code")
                .accessibilityIdentifier("pairing.code_input")
            Button("Submit") {
                Task { await viewModel.submitPairingCodeFromAlert() }
            }
            .accessibilityIdentifier("pairing.submit")
            Button("Cancel", role: .cancel) {
                viewModel.cancelPairingCodePrompt()
            }
            .accessibilityIdentifier("pairing.cancel")
        } message: {
            Text(
                viewModel.pairingPromptMessage.isEmpty
                    ? "Enter the 6-digit code shown on the device."
                    : viewModel.pairingPromptMessage
            )
            .accessibilityIdentifier("pairing.prompt")
        }
    }

    @ViewBuilder
    private var platformContent: some View {
        #if os(iOS)
        IOSContentView(viewModel: viewModel)
        #else
        MacContentView(viewModel: viewModel)
        #endif
    }
}
