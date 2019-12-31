package app.socks.proxy.udp;

import android.util.LruCache;

import java.net.DatagramSocket;

public class UDPLruCache extends LruCache<Integer, DatagramSocket> {

    /**
     * @param maxSize for caches that do not override {@link #sizeOf}, this is
     *                the maximum number of entries in the cache. For all other caches,
     *                this is the maximum sum of the sizes of the entries in this cache.
     */
    public UDPLruCache(int maxSize) {
        super(maxSize);
    }

    @Override
    protected void entryRemoved(boolean evicted, Integer key, DatagramSocket oldValue, DatagramSocket newValue) {
        if (!oldValue.isClosed()) {
            oldValue.close();
        }
    }
}
