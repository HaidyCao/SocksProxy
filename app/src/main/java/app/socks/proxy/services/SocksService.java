package app.socks.proxy.services;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import app.socks.proxy.Session;
import app.socks.proxy.SessionManager;
import app.socks.proxy.TCPProxyServer;
import app.socks.proxy.UDPProxyServer;
import app.socks.proxy.tcpip.IPHeader;
import app.socks.proxy.tcpip.TCPHeader;
import app.socks.proxy.udp.UDPHeader;
import app.socks.proxy.udp.UDPLruCache;
import app.socks.proxy.utils.CommonMethods;

public class SocksService extends VpnService {

    private static final String ACTION_STOP_SERVICE = "stop_ih_service";
    public static final String LOCAL_IP_STR = "10.8.0.2";
    private static final String TAG = "IHVpnService";
    private static final int MAX_UDP_CONN_CACHED = 50;
    private static int LOCAL_IP;
    private FileOutputStream mVpnOutStream;
    private static final int MUTE_SIZE = 2560;

    private IPHeader mIPHeader;
    private TCPHeader mTCPHeader;
    private UDPHeader mUDPHeader;
    private TCPProxyServer mTCPProxyServer;
    private UDPProxyServer mUDPProxyServer;

    private boolean mStop;

    private StopVpnBroadcastReceiver mStopVpnBroadcastReceiver;

    private static boolean sRunning;
    private ParcelFileDescriptor mParcelFileDescriptor;
    private ExecutorService mUDPExecutorService;
    private UDPLruCache mUDPLruCache;

    public static void startVPN(Context context) {
        context.startService(new Intent(context, SocksService.class));
    }

    public static void stopVPN(Context context) {

    }

    @Override
    public void onCreate() {
        super.onCreate();

        new Thread(new Runnable() {

            @Override
            public void run() {
                try {
                    sRunning = true;
                    mTCPProxyServer = new TCPProxyServer();
                    mTCPProxyServer.startProxy(SocksService.this, 0);
                    mTCPProxyServer.setProtectedIp(LOCAL_IP_STR);

                    mUDPLruCache = new UDPLruCache(MAX_UDP_CONN_CACHED);
                    mUDPExecutorService = Executors.newCachedThreadPool();

                    mUDPProxyServer = new UDPProxyServer(getBaseContext());
                    mUDPProxyServer.startProxy();

                    mParcelFileDescriptor = prepare();

                    mStopVpnBroadcastReceiver = new StopVpnBroadcastReceiver();
                    IntentFilter intentFilter = new IntentFilter(ACTION_STOP_SERVICE);
                    LocalBroadcastManager.getInstance(getApplicationContext()).registerReceiver(mStopVpnBroadcastReceiver, intentFilter);

                    startVpn(mParcelFileDescriptor);
                } catch (IOException e) {
                    if (!mStop) {
                        Log.i(TAG, e.getMessage(), e);
                    }
                }
            }
        }, "IH Thread").start();
    }

    private ParcelFileDescriptor prepare() {
        Builder builder = new Builder()
                .setMtu(MUTE_SIZE)
                .addAddress(LOCAL_IP_STR, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("114.114.114.114")
                .setSession("IH");
        LOCAL_IP = CommonMethods.ipStringToInt(LOCAL_IP_STR);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
//                builder.addAllowedApplication("app.android.vpntest");
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }

        return builder.establish();
    }

    private void startVpn(ParcelFileDescriptor parcelFileDescriptor) throws IOException {
        FileInputStream vpnInputStream = new FileInputStream(parcelFileDescriptor.getFileDescriptor());
        mVpnOutStream = new FileOutputStream(parcelFileDescriptor.getFileDescriptor());

        byte[] buffer = new byte[MUTE_SIZE];
        mIPHeader = new IPHeader(buffer, 0);
        mTCPHeader = new TCPHeader(buffer, 20);
        mUDPHeader = new UDPHeader(buffer, 20);
        int len;
        while ((len = vpnInputStream.read(buffer)) != -1) {
            if (len == 0) {
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                continue;
            }

            switch (mIPHeader.getProtocol()) {
                case IPHeader.TCP:
                    onTCPPacketReceived(len);
                    break;
                case IPHeader.UDP:
                    onUDPPacketReceived(len);
                    break;
            }
        }
    }

    private void onUDPPacketReceived(int size) throws IOException {
        UDPHeader udpHeader = mUDPHeader;
        udpHeader.mOffset = mIPHeader.getHeaderLength();

//        if (mUDPHeader.getSourcePort() == mUDPProxyServer.getPort()) {
//            // 从udp代理服务器发过来的
//            Session session = SessionManager.getSession(mUDPHeader.getDestinationPort());
//            if (session == null) {
//                Log.e(TAG, "not found the session of udp as response");
//                return;
//            }
//
//            mIPHeader.setSourceIP(session.mRemoteIP);
//            mUDPHeader.setSourcePort(session.mRemotePort);
//            mIPHeader.setDestinationIP(LOCAL_IP);
//
//            CommonMethods.ComputeUDPChecksum(mIPHeader, mUDPHeader);
//            mVpnOutStream.write(mIPHeader.mData, mIPHeader.mOffset, size);
//            return;
//        }

        short portKey = udpHeader.getSourcePort();

        Session session = SessionManager.getSession(portKey);
        if (session == null
                || session.mRemoteIP != mIPHeader.getDestinationIP()
                || session.mRemotePort != udpHeader.getDestinationPort()) {
            session = SessionManager.createSession(portKey,
                    mIPHeader.getDestinationIP(),
                    udpHeader
                            .getDestinationPort(),
                    IPHeader.UDP);
        }

        session.mLastUpdateDate = System.currentTimeMillis();
        session.mPacketSent++; //注意顺序

//        mIPHeader.setSourceIP(mIPHeader.getDestinationIP());
//        mIPHeader.setDestinationIP(LOCAL_IP);
//        udpHeader.setDestinationPort((short) mUDPProxyServer.getPort());
//
//        CommonMethods.ComputeUDPChecksum(mIPHeader, mUDPHeader);
//        mVpnOutStream.write(mIPHeader.mData, mIPHeader.mOffset, size);

        try {
            DatagramSocket datagramSocket = mUDPLruCache.get((int) session.mSourcePort);
            if (datagramSocket == null) {
                datagramSocket = new DatagramSocket();
                protect(datagramSocket);

                mUDPLruCache.put((int) session.mSourcePort, datagramSocket);

                final Session finalSession = session;
                final DatagramSocket finalDatagramSocket = datagramSocket;
                final byte[] finalBuffer = new byte[mIPHeader.mData.length];
                System.arraycopy(mIPHeader.mData, 0, finalBuffer, 0, finalBuffer.length);
                final IPHeader ipHeader = new IPHeader(finalBuffer, 0);
                final UDPHeader newUDPHeader = new UDPHeader(finalBuffer, 20);
                mUDPExecutorService.execute(new Runnable() {

                    @Override
                    public void run() {
                        byte[] packet = new byte[1024];
                        while (true) {
                            try {
                                DatagramPacket bufferPacket = new DatagramPacket(packet, packet.length);
                                finalDatagramSocket.receive(bufferPacket);

                                ipHeader.setDestinationIP(LOCAL_IP);
                                ipHeader.setSourceIP(finalSession.mRemoteIP);

                                ipHeader.setTotalLength(ipHeader.getHeaderLength() + UDPHeader.UDP_HEADER_LENGTH + bufferPacket.getLength());
                                newUDPHeader.setSourcePort(finalSession.mRemotePort);
                                newUDPHeader.setDestinationPort(finalSession.mSourcePort);
                                newUDPHeader.setTotalLength(UDPHeader.UDP_HEADER_LENGTH + bufferPacket.getLength());

                                // copy data
                                System.arraycopy(bufferPacket.getData(), 0, ipHeader.mData, ipHeader.mOffset + ipHeader.getHeaderLength() + UDPHeader.UDP_HEADER_LENGTH, bufferPacket.getLength());
                                CommonMethods.ComputeUDPChecksum(ipHeader, newUDPHeader);

                                mVpnOutStream.write(ipHeader.mData, ipHeader.mOffset, ipHeader.getTotalLength());
                            } catch (Exception e) {
                                IOUtils.closeQuietly(finalDatagramSocket);
                                break;
                            }
                        }
                    }
                });
            }

            byte[] msg = new byte[udpHeader.getTotalLength() - UDPHeader.UDP_HEADER_LENGTH];
            System.arraycopy(mIPHeader.mData, mIPHeader.mOffset + mIPHeader.getHeaderLength() + UDPHeader.UDP_HEADER_LENGTH, msg, 0, msg.length);

            String targetIp = CommonMethods.ipIntToString(mIPHeader.getDestinationIP());
            final DatagramPacket datagramPacket = new DatagramPacket(msg, msg.length, new InetSocketAddress(targetIp, mUDPHeader.getDestinationPort()));
            datagramSocket.send(datagramPacket);
        } catch (SocketException e) {
            Log.e(TAG, e.getMessage(), e);
        }

//        byte[] bytes = Arrays.copyOf(mIPHeader.mData, mIPHeader.mData.length);
//        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes, 0, size);
//        byteBuffer.limit(size);
//        Packet packet = new Packet(byteBuffer);
//        udpServer.processUDPPacket(packet, portKey);
    }

    private void onTCPPacketReceived(int size) throws IOException {
        // 先寻找是否有已经存在的连接
        mTCPHeader.mOffset = mIPHeader.getHeaderLength();

        short sourcePort = mTCPHeader.getSourcePort();
        if (sourcePort == mTCPProxyServer.getPort()) {
            // 从TCPProxyServer发回来的数据
            Session session = SessionManager.getSession(mTCPHeader.getDestinationPort());
            if (session != null) {
                mIPHeader.setSourceIP(mIPHeader.getDestinationIP());
                mTCPHeader.setSourcePort(session.mRemotePort);
                mIPHeader.setDestinationIP(LOCAL_IP);
                CommonMethods.ComputeTCPChecksum(mIPHeader, mTCPHeader);

                // 将数据写回到客户端
                mVpnOutStream.write(mIPHeader.mData, mIPHeader.mOffset, size);
            } else {
                Log.e(TAG, "the session of (" + mTCPHeader.getDestinationPort() + ") not found.");
            }

            return;
        }

        Session session = SessionManager.getSession(mTCPHeader.getSourcePort());
        if (session == null
                || session.mRemoteIP != mIPHeader.getDestinationIP()
                || session.mRemotePort != mTCPHeader.getDestinationPort()) {
            session = SessionManager.createSession(mTCPHeader.getSourcePort(),
                    mIPHeader.getDestinationIP(),
                    mTCPHeader.getDestinationPort(),
                    mIPHeader.getProtocol());
        }
        session.mLastUpdateDate = System.currentTimeMillis();
        session.mPacketSent++;

        // 忽略tcp第二个ack
//        int tcpDataSize = mIPHeader.getDataLength() - mTCPHeader.getHeaderLength();
//        if (session.mPacketSent == 2 && tcpDataSize == 0) {
//            return;
//        }

        // 将数据发送到TCPProxyServer
        mIPHeader.setSourceIP(mIPHeader.getDestinationIP());
        mIPHeader.setDestinationIP(LOCAL_IP);
        mTCPHeader.setDestinationPort(mTCPProxyServer.getPort());
        CommonMethods.ComputeTCPChecksum(mIPHeader, mTCPHeader);

        mVpnOutStream.write(mIPHeader.mData, mIPHeader.mOffset, size);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (mStopVpnBroadcastReceiver != null) {
            LocalBroadcastManager.getInstance(getApplicationContext()).unregisterReceiver(mStopVpnBroadcastReceiver);
        }
    }

    private class StopVpnBroadcastReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || intent.getAction() == null) {
                return;
            }

            switch (intent.getAction()) {
                case ACTION_STOP_SERVICE:
                    mStop = true;
                    IOUtils.closeQuietly(mParcelFileDescriptor);
                    sRunning = false;
                    break;
                default:
                    break;
            }
        }
    }
}
