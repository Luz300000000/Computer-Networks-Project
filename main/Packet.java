import java.util.HashMap;
import java.util.Map;

/**
 * The Class Packet.
 *
 * @author Grupo 2: Filipe Costa fc55549, Ines Luz fc57552, Sofia Pereira fc56352 
 */
public class Packet implements Comparable<Packet> {

    private Map<String, String> packetMap;

    /**
     * Instantiates a new packet.
     *
     * @param tokensArray 	  the array that contains every attribute of Packet
     */
    public Packet(String [] tokensArray) {
        packetMap = new HashMap<>();

        packetMap.put("number", tokensArray[0]);
        packetMap.put("time", tokensArray[1]);
        packetMap.put("sourceIP", tokensArray[2]);
        packetMap.put("destIP", tokensArray[3]);
        packetMap.put("sourcePort", tokensArray[4]);
        packetMap.put("destPort", tokensArray[5]);
        packetMap.put("protocol", tokensArray[6]);
        packetMap.put("type", tokensArray[7]);
        packetMap.put("length", tokensArray[8]);
        packetMap.put("flags", tokensArray[9]);
    }

    /**
     * Gets this packet's attribute map.
     *
     * @return the number
     */
    public Map<String, String> getPacketMap() {
        return packetMap;
    }

    /**
     * Gets the number.
     *
     * @return the number
     */
    public String getNumber() {
        return packetMap.get("number");
    }

    /**
     * Gets the time.
     *
     * @return the time
     */
    public String getTime() {
        return packetMap.get("time");
    }

    /**
     * Gets the source IP.
     *
     * @return the source IP
     */
    public String getSourceIP() {
        return packetMap.get("sourceIP");
    }


    /**
     * Gets the dest IP.
     *
     * @return the dest IP
     */
    public String getDestIP() {
        return packetMap.get("destIP");
    }

    /**
     * Gets the source port.
     *
     * @return the source port
     */
    public String getSourcePort() {
        return packetMap.get("sourcePort");
    }

    /**
     * Gets the dest port.
     *
     * @return the dest port
     */
    public String getDestPort() {
        return packetMap.get("destPort");
    }

    /**
     * Gets the protocol.
     *
     * @return the protocol
     */
    public String getProtocol() {
        return packetMap.get("protocol");
    }

    /**
     * Gets the type.
     *
     * @return the type
     */
    public String getType() {
        return packetMap.get("type");
    }

    /**
     * Gets the length.
     *
     * @return the length
     */
    public int getLength() {
        return Integer.parseInt(packetMap.get("length"));
    }

  
    /**
     * Gets the flags.
     *
     * @return the flags
     */
    public String getFlags() {
        return packetMap.get("flags");
    }
    
    /**
     * 
     */
    public int compareTo(Packet p) {
    	
    	if (this.getLength() > p.getLength()) {
    		return 1;
    	} else if (this.getLength() < p.getLength()) {
    		return -1;
    	}
    	
    	return 0;
    }

    /**
     * To string.
     *
     * @return the string
     */
    @Override
    public String toString() {
        return "Packet [number=" + getNumber() + 
            ", time=" + getTime() + 
            ", sourceIP=" + getSourceIP() + 
            ", destIP=" + getDestIP() + 
            ", sourcePort=" + getSourcePort() + 
            ", destPort=" + getDestPort() + 
            ", protocol=" + getProtocol() + 
            ", type=" + getType() + 
            ", length=" + getLength() + 
            ", flags=" + getFlags() + "]";
    }
}