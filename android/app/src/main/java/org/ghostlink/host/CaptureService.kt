package org.ghostlink.host

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.view.Surface

/** Visible, non-restarting capture service. Currently discards all encoded output locally. */
class CaptureService : Service() {
    private var projection: MediaProjection? = null
    private var display: VirtualDisplay? = null
    private var encoder: MediaCodec? = null
    private var surface: Surface? = null
    private lateinit var worker: HandlerThread
    private lateinit var handler: Handler
    private val callback = object : MediaProjection.Callback() {
        override fun onStop() { stopSelf() }
        // Android 14 app-window sharing may change size. Fail closed and require fresh consent.
        override fun onCapturedContentResize(width: Int, height: Int) {
            if (width != captureWidth || height != captureHeight) stopSelf()
        }
    }
    private var captureWidth = 0
    private var captureHeight = 0

    override fun onCreate() {
        super.onCreate()
        worker = HandlerThread("ghostlink-capture").also { it.start() }
        handler = Handler(worker.looper)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Never reuse projection tokens or create two virtual displays from one approval.
        if (projection != null) return START_NOT_STICKY
        val code = intent?.getIntExtra(EXTRA_RESULT_CODE, Activity.RESULT_CANCELED)
            ?: Activity.RESULT_CANCELED
        val data = if (Build.VERSION.SDK_INT >= 33) {
            intent?.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent?.getParcelableExtra<Intent>(EXTRA_RESULT_DATA)
        }
        if (code != Activity.RESULT_OK || data == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
            val metrics = resources.displayMetrics
            captureWidth = metrics.widthPixels / 2 * 2
            captureHeight = metrics.heightPixels / 2 * 2
            val codec = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
            encoder = codec
            codec.configure(MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC,
                captureWidth, captureHeight).apply {
                setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
                setInteger(MediaFormat.KEY_BIT_RATE, 4_000_000)
                setInteger(MediaFormat.KEY_FRAME_RATE, 30)
                setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1)
            }, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            surface = codec.createInputSurface()
            codec.start()
            projection = getSystemService(MediaProjectionManager::class.java).getMediaProjection(code, data)
            projection!!.registerCallback(callback, Handler(mainLooper))
            display = projection!!.createVirtualDisplay("GhostLink approved capture", captureWidth,
                captureHeight, metrics.densityDpi, DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                surface, null, null)
            handler.post(drain)
        } catch (_: RuntimeException) {
            // No token, frame, or screen information is logged.
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private val drain = object : Runnable {
        override fun run() {
            val codec = encoder ?: return
            try {
                val info = MediaCodec.BufferInfo()
                // Bounded work per turn; never accumulate encoded frames in an unbounded queue.
                repeat(8) {
                    val index = codec.dequeueOutputBuffer(info, 0)
                    if (index >= 0) codec.releaseOutputBuffer(index, false)
                }
                handler.postDelayed(this, 10)
            } catch (_: IllegalStateException) { stopSelf() }
        }
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Active screen sharing",
            NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 0,
            Intent(this, CaptureService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_menu_camera)
            .setContentTitle("GhostLink screen capture active")
            .setContentText("Local test only — tap Stop to revoke capture")
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    override fun onDestroy() {
        // Serialize codec release after any in-flight drain operation.
        handler.removeCallbacksAndMessages(null)
        handler.post {
            display?.release()
            display = null
            encoder?.let {
                try { it.stop() } catch (_: IllegalStateException) { }
                it.release()
            }
            encoder = null
            surface?.release()
            surface = null
            projection?.unregisterCallback(callback)
            projection?.stop()
            projection = null
            worker.quitSafely()
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val EXTRA_RESULT_CODE = "projection-result-code"
        const val EXTRA_RESULT_DATA = "projection-result-data"
        private const val ACTION_STOP = "org.ghostlink.host.STOP"
        private const val CHANNEL = "ghostlink-capture"
    }
}
