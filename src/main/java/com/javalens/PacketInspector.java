package com.javalens;

import java.util.Set;
import java.util.Objects;

// Import Packet Row
import com.javalens.Utils.PacketRow;

public class PacketInspector {
    private static final Set<Integer> ODD_TCP_PORTS = Set.of(1337, 666, 31337, 0);
    private static final int MAX_DNS_LABEL_LENGTH = 63;
    private static final int MAX_DNS_NAME_LENGTH = 255;
    private static final int ICMP_PAYLOAD_THRESHOLD = 1000; // bytes

    public static boolean suspiciousPacket(PacketRow row) {
        if (row == null || row.getProtocol() == null) return false;

        String proto = row.getProtocol().trim().toUpperCase();
        switch (proto) {
            case "TCP":
                return isSuspiciousTcp(row);
            case "UDP":
                return isSuspiciousDns(row);
            case "ICMP":
                return isSuspiciousIcmp(row);
            default:
                return false;
        }
    }

    private static boolean isSuspiciousTcp(PacketRow row) {
        Integer srcPort = row.getSrcPort(), dstPort = row.getDstPort();
    
        // Non-standard odd ports
        if (ODD_TCP_PORTS.contains(srcPort) || ODD_TCP_PORTS.contains(dstPort)) {
            return true;
        }
    
        // Tiny TCP window size with SYN — possible scan or DoS
        if (row.hasFlag("SYN") && !row.hasFlag("ACK")) {
            Integer window = row.getWindowSize();
            if (window != null && window < 100) {
                return true;
            }
        }
    
        return false;
    }    

    private static boolean isSuspiciousDns(PacketRow row) {
        Integer srcPort = row.getSrcPort(), dstPort = row.getDstPort();
    
        // Only consider packets involving DNS port 53
        if (!Objects.equals(srcPort, 53) && !Objects.equals(dstPort, 53)) {
            return false;
        }
    
        String qname = row.getDnsQueryName();
        if (qname == null) return false;
    
        // 1) Overly long domain name
        if (qname.length() > MAX_DNS_NAME_LENGTH) {
            return true;
        }
    
        // 2) Count underscores
        long underscoreCount = qname.chars().filter(c -> c == '_').count();
        if (underscoreCount > 5) {
            return true;  // Relaxed threshold
        }
    
        // 3) Check individual labels
        for (String label : qname.split("\\.")) {
            if (label.length() > MAX_DNS_LABEL_LENGTH) {
                return true;
            }
    
            // Highly random-looking subdomain (hex-only, very long)
            if (label.matches("^[0-9A-Fa-f]{32,}$")) {
                return true;
            }
    
            // (Optional) catch truly random 12+ char lowercase blocks like malware beacons
            if (label.matches("^[a-z0-9]{12,}$")) {
                return true;
            }
        }
    
        return false;
    }    

    private static boolean isSuspiciousIcmp(PacketRow row) {
        Integer type = row.getIcmpType(), code = row.getIcmpCode();
        byte[] payload = row.getPayload();

        // Echo requests with huge payloads
        if (Objects.equals(type, 8) && payload != null && payload.length > ICMP_PAYLOAD_THRESHOLD) {
            return true;
        }
        // Destination Unreachable flooding
        if (Objects.equals(type, 3) && Objects.equals(code, 1 /* host unreachable */)) {
            return true;
        }
        // Deprecated types (e.g., source quench: type 4)
        if (Objects.equals(type, 4)) {
            return true;
        }
        return false;
    }
}
