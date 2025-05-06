package com.javalens;

import java.net.URL;

//JavaFX Components and Application Framework
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.geometry.Insets;
import javafx.scene.layout.HBox;
import javafx.scene.image.Image;
import javafx.scene.input.KeyCode;
import javafx.application.Platform;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Priority;
import javafx.application.Application;
import javafx.scene.layout.BorderPane;
import javafx.animation.AnimationTimer;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.collections.transformation.FilteredList;

//PCap4j - Packet Capturing and Networking Classes
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.javalens.Utils.PacketRow;

import java.util.ArrayList;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

//Java Standard Library Imports
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import java.time.LocalTime;
import java.io.EOFException;
import java.time.format.DateTimeFormatter;

//Utility Functions
import static com.javalens.Utils.*;
public class JavaLensApp extends Application {
    // Logger
    private static final Logger logger = LoggerFactory.getLogger(JavaLensApp.class);

    // ────────────────────── UI State ─────────────────────────────────────────────────── //
    //All Captured Packets are going into this ObservableList. filtiredRows is the searchable version of Rows. 
    //While table is the TableUI component to display the packets
    private final ObservableList<PacketRow> rows = FXCollections.observableArrayList();
    private final FilteredList<PacketRow>  filteredRows = new FilteredList<>(rows, p -> true);
    private final TableView<PacketRow>     table = new TableView<>();

    //AtomicBoolean variable thats thread-safe to track whether user has the capturing button clicked or not
    private final AtomicBoolean capturing = new AtomicBoolean(false); 
    
    //button for start/stop , autoscroll checkbox button, and a boolean to know if im at the bottom or not
    private Button startStop;
    private CheckBox autoscroll = new CheckBox("AutoScroll");
    boolean stickToBottom = Utils.isAtBottom(table);
   
    //sets that help me determine the ownership of my packets
    private final Set<String> localIPs = Utils.getLocalIPAddresses();
    private final Set<String> localMACs = Utils.getLocalMACAddresses();

    //Scene buttons
    private ToggleButton themeToggle = new ToggleButton("🌙 Dark");
    private Scene scene;
    // ────────────────────── Capture Buffers && UI Flushers ─────────────────────────────────────────────────── //
    //Buffer is a thread-safe queue to temporarily hold captured packets. Main UI thread reads from this buffer.
    private final BlockingQueue<PacketRow> buffer = new LinkedBlockingQueue<>();
    private final int MAX_ROWS_PER_FRAME = 500;

    //Pop Packets from background buffer queue to the visible table UI for the user
    private final AnimationTimer flusher = new AnimationTimer() {
        @Override public void handle(long now) {
            for (int i = 0; i < MAX_ROWS_PER_FRAME; i++) {
                PacketRow r = buffer.poll();
                if (r == null) break;
                rows.add(r);
            }

            //Scroll if autoscroll is selected and rows isnt empty
            if (autoscroll.isSelected() && !rows.isEmpty()) {
                int last = rows.size() - 1;
                Platform.runLater(() -> table.scrollTo(last));
            }
        }
    };

    private ExecutorService capturePool; //My engine running the packet capture
    private ComboBox<PcapNetworkInterface> ifaceBox; //drop down for the network interface the user picks
    private TextField filterField; //textfield for search/filter

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS"); // [Example: 13:42:11.653]
    // ────────────────────── JavaFX Entry && Logic  ─────────────────────────────────────────────────── //
    @Override public void start(Stage stage) {
        stage.setTitle("JavaLens");
        stage.getIcons().add(icon());
        setMacDockIcon();

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(10));

        root.setTop(buildToolbar());
        root.setCenter(buildTable());

        scene = new Scene(root, 1120, 680);
        scene.getStylesheets().add(getClass().getResource("/css/javalens-light.css").toExternalForm());
        stage.setScene(scene);
        stage.show();

        // THEME TOGGLING LOGIC
        themeToggle.setOnAction(e -> {
            scene.getStylesheets().clear();
            if (themeToggle.isSelected()) {            // DARK
                scene.getStylesheets().add(
                    getClass().getResource("/css/javalens-dark.css").toExternalForm());
                themeToggle.setText("☀️ Light");
            } else {                                   // LIGHT
                scene.getStylesheets().add(
                    getClass().getResource("/css/javalens-light.css").toExternalForm());
                themeToggle.setText("🌙 Dark");
            }
        });

        // keyboard shortcuts
        scene.setOnKeyPressed(e -> {
            if (e.isMetaDown()) {
                if (e.getCode() == KeyCode.R) toggleCapture(); // ⌘R = Start/Stop capture
                else if (e.getCode() == KeyCode.L) rows.clear(); // ⌘L = Clear packets
                else if (e.getCode() == KeyCode.F) filterField.requestFocus(); // ⌘F = Focus search box
            }
        });
    }

    private Image icon() { return new Image(getClass().getResourceAsStream("/images/java-lens-nobg.png")); }

    // ────────────────────── Build Tool Bar Logic ─────────────────────────────────────────────────── //
    private ToolBar buildToolbar() {
        //Logo
        ImageView logo = new ImageView(icon());
        logo.setFitHeight(26); logo.setPreserveRatio(true);
        
        //Dropdown ComoboBox - Initially set to e0 if found. Else it fallsback to the first device.
        ifaceBox = new ComboBox<>();
        List<PcapNetworkInterface> devices = findAllDevs();
        for (PcapNetworkInterface dev : devices) {
            if (dev.getName().equals("en0")) {
                ifaceBox.getSelectionModel().select(dev);
                break;
            }
        }
        if (ifaceBox.getSelectionModel().isEmpty() && !devices.isEmpty()) {
            ifaceBox.getSelectionModel().selectFirst();
        }
        ifaceBox.setPrefWidth(240);

        //Show friendly names for the network interfaces on Mac
        ifaceBox.setCellFactory(cb -> new ListCell<>() {
            @Override protected void updateItem(PcapNetworkInterface ni, boolean empty) {
                super.updateItem(ni, empty);
                setText(empty || ni == null
                    ? ""
                    : (ni.getDescription() != null ? ni.getDescription() : ni.getName()));
            }
        });
        ifaceBox.setButtonCell(ifaceBox.getCellFactory().call(null));        

        //Control Buttons && their functionalities
        startStop = new Button("▶ Start");
        startStop.setOnAction(e -> toggleCapture());

        Button clear = new Button("🗑 Clear");
        clear.setOnAction(e -> rows.clear());

        Button tcpFilter = new Button("TCP");
        Button udpFilter = new Button("UDP");
        Button httpFilter = new Button("HTTP");
        Button clearFilter = new Button ("🔄 Clear Filter");
        Button statsButton = new Button("Statistics");
        
        tcpFilter.setOnAction(e -> filterField.setText("tcp"));
        udpFilter.setOnAction(e -> filterField.setText("udp"));
        httpFilter.setOnAction(e -> filterField.setText("http"));
        clearFilter.setOnAction(e -> filterField.clear());
        statsButton.setOnAction(e -> showProtocolStats(rows));
        
        tcpFilter.setPrefWidth(60);
        udpFilter.setPrefWidth(60);
        httpFilter.setPrefWidth(60);
        clearFilter.setPrefWidth(100);
        statsButton.setPrefWidth(80);

        //Search Box
        filterField = new TextField();
        filterField.setPromptText("Filter (src/dst/contains)…");

        //Live MATCHES what the user types to match search terms using filteredRows
        filterField.textProperty().addListener((obs, oldV, newV) ->
            filteredRows.setPredicate(r -> newV == null || newV.isBlank() || r.matches(newV)));

        HBox spacer = new HBox(); HBox.setHgrow(spacer, Priority.ALWAYS); //toolbar to far right

        //build tool bar and return it
        ToolBar tb = new ToolBar(
            logo, new Separator(),
            ifaceBox, new Separator(),
            startStop, clear,
            tcpFilter, udpFilter, httpFilter, clearFilter, statsButton,
            autoscroll, themeToggle,
            spacer,
            new Label("🔍"), filterField
        );        tb.setPadding(new Insets(6,0,6,0));
        return tb;
    }

    // ────────────────────── Table Logic ─────────────────────────────────────────────────── //
    private TableView<PacketRow> buildTable() {
        //Take the filtered live search results and wrap them in a sorted list so when the user clicks a column header, the rows are actually sorted visually
        SortedList<PacketRow> sorted = new SortedList<>(filteredRows);
        sorted.comparatorProperty().bind(table.comparatorProperty());
        table.setItems(sorted); //display them now

        //auto-size
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_ALL_COLUMNS);

        // PACKET: [ TIME | SRC | DST | POROT | LEN | INFO ] 
        List<TableColumn<PacketRow, String>> columns = List.of(
            col("Time", 120, "time"),
            col("Source", 200, "source"),
            col("Destination", 200, "destination"),
            col("Proto", 70,  "protocol"),
            col("Len",   70,  "length"),
            col("Info",  450, "info")
        );
        table.getColumns().addAll(columns);
        table.getColumns().add(helpCol());

        //On mouse click if a user clicks a non empty row, a dialog opens up showing the full packet details with .getItem()
        table.setRowFactory(tv -> {
            TableRow<PacketRow> row = new TableRow<>();
            row.setOnMouseClicked(ev -> {
                if (ev.getClickCount() == 2 && !row.isEmpty()) showDetails(row.getItem());
            });
            return row;
        });
        return table;
    }

    //Helper for the table columns
    private TableColumn<PacketRow,String> col(String title,int min,String prop){
        TableColumn<PacketRow,String> c = new TableColumn<>(title);
        c.setMinWidth(min); 
        c.setCellValueFactory(new PropertyValueFactory<>(prop));
        return c;
    }

    //A column specifically for showing an explanation on the type of packet currently chosen
    private TableColumn<PacketRow,Void> helpCol() {
        TableColumn<PacketRow,Void> c = new TableColumn<>("Explanation of Type");
        c.setMinWidth(35);
        c.setStyle("-fx-alignment:CENTER;");
    
        c.setCellFactory(tc -> new TableCell<>() {
            private final Button btn = new Button("❓");
            {
                btn.setStyle("-fx-background-color:transparent; -fx-cursor:hand;");
                btn.setTooltip(new Tooltip());
                btn.setOnAction(e ->
                    Utils.showExplain(getTableView().getItems().get(getIndex())));
            }
            @Override protected void updateItem(Void v, boolean empty) {
                super.updateItem(v, empty);
                if (empty) { setGraphic(null); }
                else {
                    PacketRow r = getTableView().getItems().get(getIndex());
                    btn.getTooltip().setText(Utils.explain(r));
                    setGraphic(btn);
                }
            }
        });
        return c;
    }

    // ────────────────────── Capture Control - Under the Hood Logic of JavaLens ─────────────────────────────────────────────────── //
    //Toggles the capture on/off button when the user clicks the button or does command+R
    private void toggleCapture() {
        if (capturing.get()) stopCapture();
        else startCapture();
    }

    //starts flushing and capturing if and only if the atomicboolean is not already set to true
    private void startCapture() {
        if (capturing.getAndSet(true)) return;

        flusher.start();
        startStop.setText("⏹ Capturing...");
        logger.info("Packet capture started on interface: {}", ifaceBox.getValue().getName());
        capturePool = Executors.newSingleThreadExecutor();
        PcapNetworkInterface nif = ifaceBox.getValue();
        capturePool.submit(() -> sniffLoop(nif));
    }

    //set atomic boolean to false, text to start, and shutdown the capturePool
    private void stopCapture() {
        capturing.set(false);
        startStop.setText("▶ Start");
        logger.info("Packet capture stopped.");
        if (capturePool != null) capturePool.shutdownNow();
    }

    //Open the selected network interface in PROMISCUOUS MODE to capture all the traffic. Keep capturing as long as capturing is true. 
    private void sniffLoop(PcapNetworkInterface nif) {
        logger.info("Initializing packet capture on interface: {}", nif.getName());

        try {
            PcapHandle h = nif.openLive(
                65_536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                1_000
            );
            try (h) {
                logger.info("Successfully opened interface {} for live capture.", nif.getName());
    
                while (capturing.get()) {
                    try {
                        Packet p = h.getNextPacketEx();
                        if (p != null) {
                            PacketRow row = parsePacket(p);
                            buffer.offer(row);
                            logger.debug("Captured packet: {}", row.getInfo());
                        }
                    } catch (TimeoutException e) {
                        logger.debug("Capture timeout: {}", e.getMessage());
                    } catch (EOFException e) {
                        logger.warn("Capture reached EOF unexpectedly: {}", e.getMessage());
                    } catch (NotOpenException e) {
                        logger.error("Capture handle was closed unexpectedly: {}", e.getMessage());
                        break;
                    } catch (Exception e) {
                        logger.error("Unexpected error during capture: {}", e.toString());
                    }
                }
            }
        } catch (PcapNativeException ex) {
            logger.error("Failed to start capture on {}: {}", nif.getName(), ex.getMessage());
            Platform.runLater(() -> showAlert("Capture stopped", ex.getMessage()));
        }
    }

    // ────────────────────── Parse Packet - Under the Hood Logic Part 2 of JavaLens ─────────────────────────────────────────────────── //
    //This method will analyze the raw Pcap4j packet and convert it into a PacketRow object for the TableUI
    private PacketRow parsePacket(Packet p) {
        String src = "?", dst = "?", proto = p.getClass().getSimpleName(), info = "";
        if (p.contains(IpPacket.class)) {
            IpPacket ip = p.get(IpPacket.class);
            src = ip.getHeader().getSrcAddr().getHostAddress()
                    .replaceAll("%.*","").toLowerCase();
            dst = ip.getHeader().getDstAddr().getHostAddress()
                    .replaceAll("%.*","").toLowerCase();
            IpNumber in = ip.getHeader().getProtocol();
            proto = (in == IpNumber.TCP ? "TCP" : in == IpNumber.UDP ? "UDP" : in.name());
    
            if (proto.equals("TCP") && p.contains(TcpPacket.class)) {
                TcpPacket tcp = p.get(TcpPacket.class);
                info = "TCP " + tcp.getHeader().getSrcPort() + " → " + tcp.getHeader().getDstPort();
            } else if (proto.equals("UDP") && p.contains(UdpPacket.class)) {
                UdpPacket udp = p.get(UdpPacket.class);
                info = "UDP " + udp.getHeader().getSrcPort() + " → " + udp.getHeader().getDstPort();
            } else {
                info = proto + " packet";
            }
        } else {
            info = proto + " packet";
        }

        
        String ethSrc = "?", ethDst = "?";
        boolean isMine = false;
        boolean isBroadcastOrMulticast = false;

        // Match the MAC Address
        if (p.contains(org.pcap4j.packet.EthernetPacket.class)) {
            var eth = p.get(org.pcap4j.packet.EthernetPacket.class);

            ethSrc = Utils.macToString(eth.getHeader().getSrcAddr().getAddress());
            ethDst = Utils.macToString(eth.getHeader().getDstAddr().getAddress());

            // Broadcast MAC
            if ("ff:ff:ff:ff:ff:ff".equals(ethDst)) {
                isBroadcastOrMulticast = true;
            }

            // Multicast MACs (IPv4 and IPv6)
            if (ethDst.startsWith("01:00:5e") || ethDst.startsWith("33:33") || ethDst.startsWith("01:80:c2")) {
                isBroadcastOrMulticast = true;
            }

            if (localMACs.contains(ethSrc) || localMACs.contains(ethDst)) {
                isMine = true;
            }
        }

        // IP Address
        if (!isMine && (localIPs.contains(src) || localIPs.contains(dst))) {
            isMine = true;
        }

        PacketRow row = new PacketRow(
            LocalTime.now().format(TIME_FMT),
            src, dst, proto,
            String.valueOf(p.length()), info,
            p.toString(), isMine, isBroadcastOrMulticast
        );

        if (Utils.suspiciousPacket(row)) {
            Database.insertPacket(row);
        }
        return row;
    }
    // ── Main -------------------------------------------------------------
    public static void main(String[] args) { launch(args); }
}
