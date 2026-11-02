package dev.hewig.hwcore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.hwcore.HostStorage
import uniffi.hwcore.HostStorageException

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val KEY_ALIAS = "hwcore-host-snapshot"
private const val CIPHER = "AES/GCM/NoPadding"
private const val IV_BYTES = 12
private const val TAG_BITS = 128

/** Keep [file] outside Auto Backup: the Keystore key does not transfer to a restored device. */
class KeystoreHostStorage(file: File) : HostStorage {
    private val file = AtomicFile(file)

    override fun load(): ByteArray? {
        if (!file.baseFile.exists()) {
            return null
        }
        return guarded("read") {
            val stored = file.readFully()
            val key = existingKey() ?: throw GeneralSecurityException("Keystore key is missing")
            val cipher = Cipher.getInstance(CIPHER)
            val iv = GCMParameterSpec(TAG_BITS, stored, 0, IV_BYTES)
            cipher.init(Cipher.DECRYPT_MODE, key, iv)
            cipher.doFinal(stored, IV_BYTES, stored.size - IV_BYTES)
        }
    }

    override fun persist(snapshot: ByteArray) {
        guarded("write") {
            val cipher = Cipher.getInstance(CIPHER)
            cipher.init(Cipher.ENCRYPT_MODE, existingKey() ?: generateKey())
            val encrypted = cipher.iv + cipher.doFinal(snapshot)
            file.baseFile.parentFile?.mkdirs()
            val stream = file.startWrite()
            try {
                stream.write(encrypted)
                file.finishWrite(stream)
            } catch (error: Exception) {
                file.failWrite(stream)
                throw error
            }
        }
    }

    private fun existingKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getKey(KEY_ALIAS, null) as? SecretKey
    }

    private fun generateKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            .apply { init(spec) }
            .generateKey()
    }

    private inline fun <T> guarded(operation: String, action: () -> T): T = try {
        action()
    } catch (error: Exception) {
        throw HostStorageException.Failed("Snapshot $operation failed: ${error.javaClass.simpleName}")
    }
}
