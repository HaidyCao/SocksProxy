package app.socks.proxy;

import androidx.annotation.Nullable;
import androidx.collection.SparseArrayCompat;

/**
 * Session Manager
 */
public class SessionManager {

    private static final SparseArrayCompat<Session> sSessionMap = new SparseArrayCompat<>();

    /**
     * 通过源端口获取session
     *
     * @param srcPort port
     * @return session
     */
    @Nullable
    public static Session getSession(short srcPort) {
        return sSessionMap.get((int) srcPort);
    }

    public static Session createSession(short sourcePort, int remoteIP, short remotePort, byte protocol) {
        Session session = new Session();

        session.mLastUpdateDate = System.currentTimeMillis();
        session.mSourcePort = sourcePort;
        session.mProtocol = protocol;
        session.mRemoteIP = remoteIP;
        session.mRemotePort = remotePort;

        synchronized (sSessionMap) {
            sSessionMap.put(sourcePort, session);
        }
        return session;
    }
}
