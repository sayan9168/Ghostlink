package org.ghostlink.host

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Explicit local consent entrypoint. No remote commands or background auto-start. */
class MainActivity : Activity() {
    private val gate = CaptureGate()
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        status = TextView(this).apply {
            text = "GhostLink Host — local capture test\n\n" +
                "No remote connection yet. Encoded frames are discarded, never saved or sent. " +
                "Android will ask which screen to share. Stop at any time using the notification."
        }
        layout.addView(status)
        layout.addView(Button(this).apply {
            text = "Approve local screen capture"
            setOnClickListener { requestCapture() }
        })
        layout.addView(Button(this).apply {
            text = "Stop capture"
            setOnClickListener {
                stopService(Intent(this@MainActivity, CaptureService::class.java))
                gate.stop()
                status.text = "Capture stopped. A new Android approval is required to restart."
            }
        })
        setContentView(layout)
    }

    private fun requestCapture() {
        if (!gate.request()) return
        // Require visible notifications in addition to Android's system projection indicator.
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            gate.stop()
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
            status.text = "Allow notifications, then tap Approve again."
            return
        }
        val manager = getSystemService(MediaProjectionManager::class.java)
        @Suppress("DEPRECATION")
        startActivityForResult(manager.createScreenCaptureIntent(), 1)
    }

    @Deprecated("Platform callback retained for dependency-free Activity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 1) return
        if (!gate.resolve(resultCode == RESULT_OK && data != null)) {
            status.text = "Screen sharing was not approved."
            return
        }
        try {
            startForegroundService(Intent(this, CaptureService::class.java).apply {
                putExtra(CaptureService.EXTRA_RESULT_CODE, resultCode)
                putExtra(CaptureService.EXTRA_RESULT_DATA, data)
            })
            status.text = "Local capture requested. Use Stop or the notification to end it."
        } catch (_: RuntimeException) {
            gate.stop()
            status.text = "Capture could not start. Tap Approve to try again."
        }
    }
}
