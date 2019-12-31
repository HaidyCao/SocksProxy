package app.socks.proxy;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;

import app.socks.proxy.services.SocksService;
import app.socks.proxy.utils.CommonMethods;

public class UDPProxyServer {

    private static final String TAG = "UDPProxyServer";
    private DatagramSocket mDatagramSocket;

    public static final int UDP_MAX_PACKET_LENGTH = 1024;
    private byte[] mPacket = new byte[UDP_MAX_PACKET_LENGTH];

    private Context mContext;

    private int mPort;

    public UDPProxyServer(@NonNull Context context) {
        mContext = context.getApplicationContext();
    }

    public int getPort() {
        return mPort;
    }

    public void startProxy() throws SocketException {
        mDatagramSocket = new DatagramSocket();
        mPort = mDatagramSocket.getLocalPort();

        new Thread(new Runnable() {

            @Override
            public void run() {
                DatagramPacket datagramPacket = new DatagramPacket(mPacket, UDP_MAX_PACKET_LENGTH);
                while (true) {
                    try {
                        mDatagramSocket.receive(datagramPacket);

                        int port = datagramPacket.getPort();

                        // 从本地发过来
                        if (SocksService.LOCAL_IP_STR.equals(datagramPacket.getAddress().getHostAddress())) {
                            Session session = SessionManager.getSession((short) port);
                            if (session == null) {
                                Log.e(TAG, "not found session");
                                return;
                            }

                            // 转发到远程地址
                            datagramPacket.setSocketAddress(new InetSocketAddress(CommonMethods.ipIntToString(session.mRemoteIP), session.mRemotePort));
                            mDatagramSocket.send(datagramPacket);
                        } else {
                            // 从服务器发过来，写回本地
//                            datagramPacket.setSocketAddress(new InetSocketAddress(IHVpnService.LOCAL_IP_STR, session.mRemotePort));
                        }




                    } catch (IOException e) {
                        Log.e(TAG, e.getMessage(), e);
                        SocksService.stopVPN(mContext);
                        break;
                    }
                }
            }
        }, "UDP Proxy Server").start();
    }
}
