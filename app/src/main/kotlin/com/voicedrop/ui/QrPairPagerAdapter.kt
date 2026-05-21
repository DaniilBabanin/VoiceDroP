package com.voicedrop.ui

import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.voicedrop.R
import com.voicedrop.crypto.KeyManager

class QrPairPagerAdapter(
    activity: FragmentActivity,
    private val keyManager: KeyManager,
    private val onScan: (String) -> Unit,
    private val onImportFile: () -> Unit,
    private val onShareFile: () -> Unit
) : FragmentStateAdapter(activity) {

    override fun getItemCount() = 3

    override fun createFragment(position: Int): Fragment = when (position) {
        0 -> MyQrFragment.newInstance(keyManager, onShareFile)
        1 -> ScanFragment.newInstance(onScan)
        2 -> ImportFileFragment.newInstance(onImportFile)
        else -> throw IllegalArgumentException("Unknown tab $position")
    }
}

class MyQrFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        inflater.inflate(R.layout.fragment_my_qr, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val cardJson = (activity as? QrPairActivity)?.getMyContactCardJson() ?: return
        val qrContent = "voicedrop://pair?card=${Uri.encode(cardJson)}"

        val qrImageView = view.findViewById<ImageView>(R.id.image_qr)
        QrEncoder.encode(qrContent, 512)?.let { qrImageView.setImageBitmap(it) }

        view.findViewById<android.widget.TextView>(R.id.text_fingerprint)?.let { fpText ->
            val keyManager = KeyManager(view.context)
            fpText.text = FingerprintFormat.format(keyManager.getFingerprint())
        }

        view.findViewById<Button>(R.id.button_share_file)?.setOnClickListener {
            (activity as? QrPairActivity)?.shareAsFile()
        }
    }

    companion object {
        fun newInstance(keyManager: KeyManager, onShareFile: () -> Unit) = MyQrFragment()
    }
}

class ScanFragment : Fragment() {
    private var barcodeView: DecoratedBarcodeView? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        inflater.inflate(R.layout.fragment_scan, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        barcodeView = view.findViewById(R.id.barcode_view)
        barcodeView?.decodeSingle { result ->
            result.text?.let { text ->
                (activity as? QrPairActivity)?.handleScannedCard(text)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        barcodeView?.resume()
    }

    override fun onPause() {
        super.onPause()
        barcodeView?.pause()
    }

    companion object {
        fun newInstance(onScan: (String) -> Unit) = ScanFragment()
    }
}

class ImportFileFragment : Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        inflater.inflate(R.layout.fragment_import_file, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        view.findViewById<Button>(R.id.button_open_file)?.setOnClickListener {
            (activity as? QrPairActivity)?.openFilePicker()
        }
    }

    companion object {
        fun newInstance(onImportFile: () -> Unit) = ImportFileFragment()
    }
}
