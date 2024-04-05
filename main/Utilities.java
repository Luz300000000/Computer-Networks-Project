import java.util.ArrayList;

public class Utilities {
    
    public static ArrayList<Packet> filterBy(ArrayList<Packet> packets, String attr, String value) {
    	ArrayList<Packet> filtered = new ArrayList<>();

        for (Packet packet : packets) {
            if (packet.getPacketMap().get(attr).equals(value)) {
                filtered.add(packet);
            }
        }
        
        return filtered; 
    }
}
