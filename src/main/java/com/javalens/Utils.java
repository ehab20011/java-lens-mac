package com.javalens;

import javafx.stage.Modality;
import javafx.scene.control.*;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.CategoryAxis;
import javafx.beans.property.SimpleStringProperty;

import java.util.Map;
import java.util.Set;
import java.awt.Taskbar;
import javax.imageio.ImageIO;

import java.util.List;
import java.util.HashSet;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Enumeration;
import java.net.SocketException;
import java.net.NetworkInterface;

import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

public class Utils {

    public static void println(Object obj) {
        System.out.println(obj);
    }
    
    public static void print(Object obj) {
        System.out.print(obj);
    }

    public static List<PcapNetworkInterface> findAllDevs() {
        try {
            return Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            showAlert("No interfaces", e.getMessage());
            return List.of();
        }
    }

    private static String prettyHex(String text) {
        byte[] bytes = text.getBytes();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
            if ((i + 1) % 16 == 0) sb.append("\n");
        }
        return sb.toString();
    }

    public static void showDetails(PacketRow r) {
        TabPane tabs = new TabPane();
        
        // [SUMMARY TAB]
        TextArea summaryArea = new TextArea(r.getFullPacketDump());
        summaryArea.setEditable(false);
        summaryArea.setWrapText(true);
        
        // [HEX VIEW TAB]
        TextArea hexArea = new TextArea(prettyHex(r.getFullPacketDump()));
        hexArea.setEditable(false);
        hexArea.setWrapText(false); 

        Tab summaryTab = new Tab("Summary", summaryArea);
        Tab hexTab = new Tab("Hex View", hexArea);
        tabs.getTabs().addAll(summaryTab, hexTab);
    
        Dialog<Void> dlg = new Dialog<>();
        dlg.setTitle("Packet Details – JavaLens");
        dlg.getDialogPane().setContent(tabs);
        dlg.getDialogPane().setMinWidth(960);
        dlg.getDialogPane().setMinHeight(580);
        dlg.getDialogPane().setPrefSize(960, 580);
        dlg.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
        dlg.setResizable(true);
        dlg.initModality(Modality.APPLICATION_MODAL);
        dlg.showAndWait();
    }

    public static void showAlert(String title, String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg, ButtonType.OK);
        a.setHeaderText(title);
        a.show();
    }

    public static boolean isAtBottom(TableView<?> table) {
        ScrollBar vBar = (ScrollBar) table.lookup(".scroll-bar:vertical");
        if (vBar == null) return true;
        return vBar.getValue() >= vBar.getMax();
    }

    public static void setMacDockIcon() {
        if (Taskbar.isTaskbarSupported()) {
            try {
                java.awt.Image dockImg = ImageIO.read(Utils.class.getResource("/images/java-lens-nobg.png"));
                Taskbar.getTaskbar().setIconImage(dockImg);
            } catch (IOException e) {
                System.err.println("Could not load dock icon: " + e.getMessage());
            } catch (NullPointerException e) {
                System.err.println("Dock icon resource not found.");
            }
        }
    }

    public static void showExplain(PacketRow r) {
        Alert a = new Alert(Alert.AlertType.INFORMATION);
        a.setTitle("What is this packet?");
        a.setHeaderText(r.getProtocol() + " packet");
        a.setContentText(shortExplain(r));
        a.showAndWait();
    }

    public static String explain(PacketRow r) {
        return shortExplain(r);
    }

    private static String shortExplain(PacketRow r) {
        String key = EXPLAIN.keySet().stream()
        .filter(k -> r.getProtocol().equalsIgnoreCase(k) ||
                                      r.getInfo().toUpperCase().contains(k))
                         .findFirst().orElse("OTHER");
            return EXPLAIN.get(key);
    }
        
    private static final Map<String, String> EXPLAIN = Map.ofEntries(
        Map.entry("TCP", 
            "TCP – Transmission Control Protocol. Reliable, connection-oriented transport layer protocol using a 3-way handshake, acknowledgments, retransmissions, and congestion control. Used for web browsing (HTTP/HTTPS), email (SMTP), file transfers (FTP)."
        ),
        Map.entry("UDP", 
            "UDP – User Datagram Protocol. Lightweight, connectionless transport layer protocol with no guarantee of delivery, ordering, or duplicate protection. Used for streaming (video, voice), DNS queries, and gaming."
        ),
        Map.entry("DNS", 
            "DNS – Domain Name System. Resolves human-readable domain names like 'google.com' into IP addresses. Typically uses UDP port 53, but can use TCP for larger responses like zone transfers."
        ),
        Map.entry("DHCP", 
            "DHCP – Dynamic Host Configuration Protocol. Automatically assigns IP addresses, subnet masks, default gateways, and DNS servers to devices on a network. Operates over UDP ports 67 (server) and 68 (client)."
        ),
        Map.entry("ARP", 
            "ARP – Address Resolution Protocol. Maps an IPv4 address to a device's MAC address inside a local Ethernet network. Uses broadcast frames (ff:ff:ff:ff:ff:ff) to find the MAC address for a given IP."
        ),
        Map.entry("HTTP", 
            "HTTP – HyperText Transfer Protocol. Application layer protocol used for web traffic (port 80). It defines how browsers and web servers communicate, requesting and transmitting web pages, images, and resources."
        ),
        Map.entry("HTTPS", 
            "HTTPS – Secure version of HTTP (over TLS/SSL). Encrypts data between browser and server to ensure privacy, authenticity, and integrity. Commonly runs over TCP port 443."
        ),
        Map.entry("FTP", 
            "FTP – File Transfer Protocol. Transfers files between client and server over TCP, using ports 20 (data) and 21 (control). Unencrypted by default; sensitive to firewalls due to separate control and data connections."
        ),
        Map.entry("ICMP", 
            "ICMP – Internet Control Message Protocol. Used for diagnostic and error messages like 'ping' (echo request/reply) and 'destination unreachable'. Operates directly over IP (not TCP/UDP)."
        ),
        Map.entry("SSH", 
            "SSH – Secure Shell. Provides encrypted remote login and command execution between computers. Runs over TCP port 22, replacing older, insecure protocols like Telnet and Rlogin."
        ),
        Map.entry("TLS", 
            "TLS – Transport Layer Security. Cryptographic protocol providing privacy and data integrity between two communicating applications. Commonly used to secure HTTPS, SMTP, and VPN traffic."
        ),
        Map.entry("NTP", 
            "NTP – Network Time Protocol. Synchronizes clocks of computer systems over packet-switched, variable-latency networks. Uses UDP port 123."
        ),
        Map.entry("SMTP", 
            "SMTP – Simple Mail Transfer Protocol. Protocol for sending emails across networks. Typically uses TCP port 25 (unencrypted) or ports 465/587 (encrypted with SSL/TLS)."
        ),
        Map.entry("POP3", 
            "POP3 – Post Office Protocol version 3. Email retrieval protocol that downloads messages from a server to a local client, usually TCP port 110 (unencrypted) or 995 (encrypted)."
        ),
        Map.entry("IMAP", 
            "IMAP – Internet Message Access Protocol. Email retrieval protocol that allows syncing and managing mail on the server. Typically TCP port 143 (unencrypted) or 993 (encrypted)."
        ),
        Map.entry("OTHER",
            "Unknown or unsupported protocol. Could be a custom, experimental, or proprietary traffic type not recognized by this tool."
        )
    );

    public static void showProtocolStats(List<PacketRow> rows) {
        // Count protocols
        var counts = new java.util.HashMap<String, Integer>();
        int total = 0;
        for (PacketRow r : rows) {
            counts.merge(r.getProtocol(), 1, Integer::sum);
            total++;
        }
        if (total == 0) {
            showAlert("No Packets", "No captured packets to show statistics for.");
            return;
        }

        // Build the BarChart
        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis yAxis = new NumberAxis();
        BarChart<String, Number> chart = new BarChart<>(xAxis, yAxis);
        chart.setTitle("Protocol Breakdown");
        chart.setLegendVisible(false);
        xAxis.setLabel("Protocol");
        yAxis.setLabel("Packets (%)");

        XYChart.Series<String, Number> series = new XYChart.Series<>();
        for (var entry : counts.entrySet()) {
            String proto = entry.getKey();
            int count = entry.getValue();
            double percent = (count * 100.0) / total;
    
            XYChart.Data<String, Number> bar = new XYChart.Data<>(proto, percent);
            
            Tooltip tooltip = new Tooltip(proto + ": " + count + " packets");
            Tooltip.install(bar.getNode(), tooltip);
            series.getData().add(bar);
        }
        chart.getData().add(series);

        // Show inside a Dialog
        Dialog<Void> dlg = new Dialog<>();
        dlg.setTitle("Traffic Statistics – JavaLens");
        dlg.getDialogPane().setContent(chart);
        dlg.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
        dlg.setResizable(true);
        dlg.setWidth(500);
        dlg.setHeight(400);
        dlg.showAndWait();
    }

    public static class PacketRow {
        private final SimpleStringProperty time, source, destination, protocol, length, info;
        private final String fullPacketDump;
        private final boolean isMine;
        private final boolean isBroadcastOrMulticast;
        private Integer srcPort;
        private Integer dstPort;
        private Integer windowSize;
        private Set<String> tcpFlags = Set.of();
        private String dnsQueryName;
        private Integer icmpType;
        private Integer icmpCode;
        private byte[] payload;

        public PacketRow(
            String t, String s, String d, String pr, String l, String i, String fullDump,
            boolean isMine, boolean isBroadcastOrMulticast,
            Integer srcPort, Integer dstPort, Integer windowSize,
            Set<String> tcpFlags, String dnsQueryName,
            Integer icmpType, Integer icmpCode, byte[] payload
        ) {
            time = new SimpleStringProperty(t);
            source = new SimpleStringProperty(s);
            destination = new SimpleStringProperty(d);
            protocol = new SimpleStringProperty(pr);
            length = new SimpleStringProperty(l);
            info = new SimpleStringProperty(i);
            fullPacketDump = fullDump;
            this.isMine = isMine;
            this.isBroadcastOrMulticast = isBroadcastOrMulticast;
            
            //metadata for the packet
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.windowSize = windowSize;
            this.tcpFlags = tcpFlags != null ? tcpFlags : Set.of();
            this.dnsQueryName = dnsQueryName;
            this.icmpType = icmpType;
            this.icmpCode = icmpCode;
            this.payload = payload;
        }

        public boolean isMine() { return isMine; }
        public boolean isBroadcastOrMulticast() { return isBroadcastOrMulticast; }
        public String getTime() { return time.get(); }
        public String getSource() { return source.get(); }
        public String getDestination() { return destination.get(); }
        public String getProtocol() { return protocol.get(); }
        public String getLength() { return length.get(); }
        public String getInfo() { return info.get(); }
        public String getFullPacketDump() { return fullPacketDump; }
        public Integer getSrcPort() { return srcPort; }
        public Integer getDstPort() { return dstPort; }
        public Integer getWindowSize() { return windowSize; }
        public boolean hasFlag(String flag) { return tcpFlags.contains(flag); }
        public String getDnsQueryName() { return dnsQueryName; }
        public Integer getIcmpType() { return icmpType; }
        public Integer getIcmpCode() { return icmpCode; }
        public byte[] getPayload() { return payload; }
        
        public boolean matches(String q) {
            String lower = q.toLowerCase();
            return getSource().toLowerCase().contains(lower)
                || getDestination().toLowerCase().contains(lower)
                || getInfo().toLowerCase().contains(lower);
        }
    }

    public static Set<String> getLocalIPAddresses() {
        Set<String> ips = new HashSet<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                for (InetAddress addr : Collections.list(iface.getInetAddresses())) {
                    ips.add(addr.getHostAddress()
                    .replaceAll("%.*","")
                    .toLowerCase()); 
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return ips;
    }
    
    public static Set<String> getLocalMACAddresses() {
        Set<String> macs = new HashSet<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;
    
                byte[] mac = ni.getHardwareAddress();
                if (mac != null && mac.length == 6) {
                    macs.add(macToString(mac));
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return macs;
    }

    public static boolean isMine(Packet p, Set<String> localMACs) {
        if (!p.contains(EthernetPacket.class)) return false;

        var eth = p.get(EthernetPacket.class);
        String src = macToString(eth.getHeader().getSrcAddr().getAddress());
        String dst = macToString(eth.getHeader().getDstAddr().getAddress());

        if (localMACs.contains(src)) {
            return true;
        }

        boolean unicast = (eth.getHeader().getDstAddr().getAddress()[0] & 0x01) == 0;
        if (unicast && localMACs.contains(dst)) {
            return true;
        }

        return false;
    }

    public static String macToString(byte[] macBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < macBytes.length; i++) {
            sb.append(String.format("%02x", macBytes[i]));
            if (i < macBytes.length - 1) sb.append(":");
        }
        return sb.toString();
    }
}
