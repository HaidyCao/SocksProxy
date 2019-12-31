package app.socks.proxy;

public class Session {

    public byte mProtocol;

    public int mRemoteIP;
    public short mRemotePort;
    public short mSourcePort;

    public long mLastUpdateDate;

    /**
     * 发送包的次数
     */
    public int mPacketSent;
}
