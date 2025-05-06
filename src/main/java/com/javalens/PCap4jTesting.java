package com.javalens;

import java.util.ArrayList;

//PCap4j - Packet Capturing and Networking Classes
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

//Java Standard Library Imports
import java.util.List;
import java.util.concurrent.TimeoutException;


//Utility Functions
import static com.javalens.Utils.*;

public class PCap4jTesting 
{
    public static void main( String[] args )
    {
        try{
            //printAllDevicesAndTheirIPs();
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();

            int mainNetIndex = getMainNetworkInterfaceIndex(interfaces);
            PcapNetworkInterface mainDevice = null;

            if(mainNetIndex == -1){
                println("Could not find main interface (en0)");
            }
            else{
                mainDevice = interfaces.get(mainNetIndex - 1);
                println("Main Interface: " + mainDevice.getName());
            }

            //get some random packets from your main device
            int MAX_PACKETS = 10;
            for(int i=1; i<=MAX_PACKETS; i++){
                println("Loading Packet [" + i + "]");
                getRandomPacket(mainDevice);
            }

        }
        catch(Exception error){
            error.printStackTrace();
        }
    }
    public static void printAllDevicesAndTheirIPs(){
        try{
            List<PcapNetworkInterface> interfaces = new ArrayList<>();
            interfaces = Pcaps.findAllDevs();

            if(interfaces.isEmpty()){ println("No Network Interfaces found!"); return; }

            //Print all the network interfaces
            int i = 1;
            for(PcapNetworkInterface device : interfaces){
                System.out.println("[" + i + "]" + device.getName());

                List<PcapAddress> currInterfaceIPAddresses = device.getAddresses();
                
                int j = 0;
                if(currInterfaceIPAddresses.isEmpty()){println("No IP addresses for this interface");}else{
                    println("IP Addresses for this interface: ");
                    for(PcapAddress ipaddress : currInterfaceIPAddresses) { println("[" + j + "]" + ipaddress); j++; }
                }

                println("Hash Code for this Interface: " + device.hashCode());
                if(device.isLoopBack()){
                    println("Interface is a loopback interface (e.g localhost or 127.0.0.1) ");
                }

                println("----------------------------------------------------------------------");
                i++;
            }
        }
        catch(Exception error){
            error.printStackTrace();
        }
    }
    public static int getMainNetworkInterfaceIndex(List<PcapNetworkInterface> interfaces) {
        try {
            if (interfaces.isEmpty()) {
                println("No Network Interfaces found!");
                return -1;
            }
    
            int i = 1;
            for (PcapNetworkInterface device : interfaces) {
                String name = device.getName();
                println("[" + i + "] " + name);
                
                // Try to pick a real Ethernet interface, avoid loopback
                if (!device.isLoopBack() && name.toLowerCase().contains("npf") && device.getAddresses().size() > 0) {
                    println(" Found usable interface: " + name);
                    return i;
                }
                i++;
            }
    
            println("No suitable main interface found.");
            return -1;
    
        } catch (Exception error) {
            error.printStackTrace();
            return -1;
        }
    }
    public static void getRandomPacket(PcapNetworkInterface mainDevice){
        try{
            PcapHandle handle = mainDevice.openLive(
                65536, //max bytes per packet to capture
                PromiscuousMode.PROMISCUOUS, // see all packets
                5000 // read timeout in milliseconds
            );

            println("Waiting for the packet... ");
            Packet packet = handle.getNextPacketEx();

            println("Packet Captured at: " + handle.getTimestamp());
            println(packet.toString());

            handle.close();
        }
        catch(TimeoutException timeout){
            println("No packet captured within timeout window.");
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    public static List<Packet> capturePackets(int maxPackets) {
        List<Packet> packets = new ArrayList<>();
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            int mainNetIndex = getMainNetworkInterfaceIndex(interfaces);
            if (mainNetIndex == -1) {
                System.out.println("No main interface found (en0).");
                return packets;
            }
    
            PcapNetworkInterface mainDevice = interfaces.get(mainNetIndex - 1);
            PcapHandle handle = mainDevice.openLive(
                65536,
                PromiscuousMode.PROMISCUOUS,
                5000
            );
    
            for (int i = 0; i < maxPackets; i++) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    packets.add(packet);
                } catch (TimeoutException e) {
                    System.out.println("Timeout while waiting for packet " + (i + 1));
                }
            }
    
            handle.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return packets;
    }
}
