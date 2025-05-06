package com.javalens;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import com.javalens.Utils.PacketRow;

import io.github.cdimascio.dotenv.Dotenv;

public class Database {
    private static final Dotenv dotenv = Dotenv.load();

    private static final String URL = dotenv.get("DB_URL");
    private static final String USER = dotenv.get("DB_USER");
    private static final String PASSWORD = dotenv.get("DB_PASSWORD");

    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    public static void insertPacket(PacketRow packet) {
    String sql = "INSERT INTO captured_packets(time, source, destination, protocol, length, info, is_mine, is_broadcast_or_multicast) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, packet.getTime());
        pstmt.setString(2, packet.getSource());
        pstmt.setString(3, packet.getDestination());
        pstmt.setString(4, packet.getProtocol());
        pstmt.setInt(5, Integer.parseInt(packet.getLength()));
        pstmt.setString(6, packet.getInfo());
        pstmt.setBoolean(7, packet.isMine());
        pstmt.setBoolean(8, packet.isBroadcastOrMulticast());
        pstmt.executeUpdate();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}

}
