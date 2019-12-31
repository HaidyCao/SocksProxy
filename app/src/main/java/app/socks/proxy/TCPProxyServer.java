package app.socks.proxy;

import android.net.VpnService;
import android.util.Log;

import androidx.annotation.NonNull;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import app.socks.proxy.utils.CommonMethods;

public class TCPProxyServer {

    private static final String TAG = "TCPProxyServer";
    private boolean mRunning;
    private ServerSocket mServerSocket;
    private ExecutorService mExecutorService;
    private String mProtectedIp;
    private VpnService mVpnService;

    private int mPort;

    private RemoteSocketFactory mRemoteSocketFactory;

    public boolean isRunning() {
        return mRunning;
    }

    public void setProtectedIp(@NonNull String ip) {
        mProtectedIp = ip;
    }

    public short getPort() {
        return (short) mPort;
    }

    public void startProxy(final VpnService service, int port) throws IOException {
        mVpnService = service;
        mExecutorService = Executors.newCachedThreadPool();
        mServerSocket = new ServerSocket(port);
        mPort = mServerSocket.getLocalPort();
        mRunning = true;

        new Thread(new Runnable() {

            @Override
            public void run() {
                while (true) {
                    final Socket socket;
                    try {
                        socket = mServerSocket.accept();
                        if (!service.protect(socket)) {
                            Log.e(TAG, "protect " + socket + " failed.");
                            return;
                        }
                    } catch (IOException e) {
                        if (mServerSocket.isClosed()) {
                            break;
                        }
                        continue;
                    }

                    mExecutorService.execute(new Runnable() {

                        @Override
                        public void run() {
                            proxy(socket);
                        }
                    });
                }
                mRunning = false;
            }
        }, "TCPProxyServer").start();
    }

    private void proxy(final Socket socket) {
        SocketAddress remoteAddress = socket.getRemoteSocketAddress();
//        if (remoteAddress instanceof InetSocketAddress) {
//            if (mProtectedIp != null && !mProtectedIp.equals(((InetSocketAddress) remoteAddress).getAddress().getHostAddress())) {
//                Log.e(TAG, "ip: " + ((InetSocketAddress) remoteAddress).getAddress().getHostAddress() + " is not protected.");
//                IOUtils.closeQuietly(socket);
//                return;
//            }
//        }

        // 找到真正的服务器ip和端口号
        Session session = SessionManager.getSession((short) socket.getPort());
        if (session == null) {
            Log.e(TAG, "address: " + remoteAddress.toString() + " session not found.");
            IOUtils.closeQuietly(socket);
            return;
        }

        Socket remoteSocket;
        String ip = CommonMethods.ipIntToString(session.mRemoteIP);
        try {
            remoteSocket = new Socket();
            remoteSocket.bind(new InetSocketAddress(0));
            mVpnService.protect(remoteSocket);
            if (mRemoteSocketFactory != null) {
                remoteSocket = mRemoteSocketFactory.createSocket(socket, ip, session.mRemotePort);
            } else {
                remoteSocket.connect(new InetSocketAddress(ip, session.mRemotePort));
            }
        } catch (IOException e) {
            Log.e(TAG, "address: "
                + remoteAddress.toString()
                + " cannot connect to remote server [" + ip + ":" + session.mRemotePort + "].", e);
            return;
        }

        // 开始传输数据
        connect(socket, remoteSocket);
        connect(remoteSocket, socket);
    }

    private void connect(final Socket s1, final Socket s2) {
        mExecutorService.execute(new Runnable() {

            @Override
            public void run() {
                try {
                    IOUtils.copyLarge(s1.getInputStream(), s2.getOutputStream());
                } catch (IOException e) {
                    Log.e(TAG, e.getMessage(), e);

                    IOUtils.closeQuietly(s1);
                    IOUtils.closeQuietly(s2);
                }
            }
        });
    }

    public void stopServer() {
        if (mExecutorService != null) {
            mExecutorService.shutdown();
        }

        if (mServerSocket != null && !mServerSocket.isClosed()) {
            IOUtils.closeQuietly(mServerSocket);
        }
        mServerSocket = null;
    }

    public interface RemoteSocketFactory {

        Socket createSocket(Socket socket, String host, int port) throws IOException;
    }
}
