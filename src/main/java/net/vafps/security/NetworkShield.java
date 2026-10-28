package net.vafps.security;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Socket-level network shield implementing CIDR range filtering and IPv4-mapped IPv6 normalization.
 */
public class NetworkShield {

    private final boolean localOnly;
    private final List<CidrRange> allowedRanges = new ArrayList<>();

    public NetworkShield(boolean localOnly, List<String> allowedCidrs) {
        this.localOnly = localOnly;
        if (allowedCidrs != null) {
            for (String cidr : allowedCidrs) {
                try {
                    this.allowedRanges.add(CidrRange.parse(cidr));
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Checks if the given remote address is allowed by the shield.
     */
    public boolean isAllowed(InetAddress address) {
        if (!localOnly) {
            return true;
        }
        InetAddress normalized = normalize(address);
        for (CidrRange range : allowedRanges) {
            if (range.contains(normalized)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Normalizes IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1).
     */
    public static InetAddress normalize(InetAddress address) {
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF) {
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(bytes, 12, ipv4Bytes, 0, 4);
                try {
                    return InetAddress.getByAddress(ipv4Bytes);
                } catch (UnknownHostException ignored) {
                }
            }
        }
        return address;
    }

    private static class CidrRange {
        private final boolean isIpv4;
        private final BigInteger network;
        private final BigInteger mask;

        private CidrRange(boolean isIpv4, BigInteger network, BigInteger mask) {
            this.isIpv4 = isIpv4;
            this.network = network;
            this.mask = mask;
        }

        public static CidrRange parse(String cidr) throws UnknownHostException {
            String[] parts = cidr.trim().split("/");
            InetAddress ip = InetAddress.getByName(parts[0]);
            ip = normalize(ip);
            boolean isIpv4 = ip instanceof Inet4Address;
            int totalBits = isIpv4 ? 32 : 128;
            int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : totalBits;

            BigInteger ipNum = new BigInteger(1, ip.getAddress());
            BigInteger mask = BigInteger.valueOf(2).pow(totalBits).subtract(BigInteger.ONE)
                    .xor(BigInteger.valueOf(2).pow(totalBits - prefix).subtract(BigInteger.ONE));
            BigInteger network = ipNum.and(mask);

            return new CidrRange(isIpv4, network, mask);
        }

        public boolean contains(InetAddress address) {
            boolean addrIsIpv4 = address instanceof Inet4Address;
            if (this.isIpv4 != addrIsIpv4) {
                return false;
            }
            BigInteger ipNum = new BigInteger(1, address.getAddress());
            return ipNum.and(mask).equals(network);
        }
    }
}
