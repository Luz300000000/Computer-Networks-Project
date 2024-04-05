import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.io.File;
import java.io.FileNotFoundException;

/**
 * The Class TrafficAnalysis.
 *
 * @author Grupo 2: Filipe Costa fc55549, Ines Luz fc57552, Sofia Pereira fc56352 
 */
public class TrafficAnalysis {	
	private ArrayList<Packet> packets;

    private String biggestSenderIP;
    private String biggestReceiverIP;
	private int biggestSenderBytes;
	private int biggestReceiverBytes;
	private int IPv6Count;
	private int IPv4Count;
	private int switchCount;
	private int wellKnownServicesTCP;

	public TrafficAnalysis(String file) throws FileNotFoundException {
		Scanner sc = new Scanner(new File(file));   
		this.packets = new ArrayList<Packet>();
		 
		sc.nextLine(); // consumes the header
		while (sc.hasNextLine())   { 
			String s = sc.nextLine();
			String[] tokens = s.split(",");
			String[] packetAttributes = new String[tokens.length];
			 
			// removes the double quotes
			for(int i = 0; i < tokens.length; i++) {
				packetAttributes[i] = tokens[i].replaceAll("\"","");
			}
			 
			Packet packet = new Packet(packetAttributes);
		    packets.add(packet);
		 }
         
         sc.close();

         countIPs();
         howManyICMP();
         determineBiggestReceiver();
         determineBiggestSender();
	}

/*
******************************************
* QUESTAO 1
******************************************
*/

	/**
	 * Q1 - How many IPv4, IPv6 and hostname packets.
	 * 
	 * Adds the number of packets found to each counter list
	 */
    public void countIPs() {
		IPv4Count = 0;
		IPv6Count = 0;
		switchCount = 0;
		
        for (Packet packet : packets) {
            if (validIPv4(packet.getSourceIP()) && validIPv4(packet.getDestIP())) {
		    	IPv4Count++;
		    } else if(validIPv6(packet.getSourceIP()) && validIPv6(packet.getDestIP()) ) {
		    	IPv6Count++;
		    } else {
		    	switchCount++;
		    }
        }
    }
    	
	/**
	 * Q1 - How many IPv4 packets.
	 * 
	 * @return count of IPv4 packets
	 */
	public int packetsInIPv4() {
		return IPv4Count;		
	}
	
	/**
	 * Q1 - How many IPv6 packets.
	 * 
	 * @return count of IPv6 packets
	 */ 
	public int packetsInIPv6() {
		return IPv6Count;		
	}
	
	/**
	 * Q1 - How many IPs are hostNames.
	 *  
	 * @return count of hostNames packets
	 */ 
	public int packetsWithIPHostName() {
		return switchCount;		
	}

	/**
	 * Q1 - Checks if ip is in version 4.
	 * 
	 * @param ip 	the ip
	 * @return true if ip is in version 4, false otherwise
	 */

	private boolean validIPv4 (String input) {
        String regex = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                       "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                       "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                       "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
        return input.matches(regex);
    }
	
	/**
	 * Q1 - Checks if ip is in version 6.
	 * 
	 * @param ip the ip
	 * @return true if ip is in version 6, false otherwise
	 */
	private boolean validIPv6(String input) {
    	Pattern IPv6 = Pattern
	            .compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    	
    	Pattern IPv6_compressed = Pattern
   	            .compile("^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$");

        return IPv6.matcher(input).matches() || IPv6_compressed.matcher(input).matches();
    }

/*
******************************************
* QUESTAO 2
******************************************
*/

	/**
	 * Q2 - Time of the trace.
	 * 
	 * @return duration of the trace
	 */
	public Double time() {
		return Double.valueOf(packets.get(packets.size() - 1).getTime());
	}

	/**
	 * Q2 - How many packets in the trace.
	 * 
	 * @return number of packets
	 */
	public int howManyPackets() {
		return packets.size();
	}

/*
******************************************
* QUESTAO 3
******************************************
*/
	
	/**
	 * Q3 - How many TCP ports are from a single origin.
	 * 
	 * @return number of packets
	 */
	public int onlyTCP() {
		ArrayList<Packet> TCPpackets = Utilities.filterBy(packets, "protocol", "TCP");

		List<String> TCPpacketsIPUniques = new ArrayList<>(); // list of unique IPs
		ArrayList<Packet> TCPUniques = new ArrayList<>(); // list of the correspondent unique packets from TCPpacketsIPUniques
		ArrayList<Packet> reservedPorts = new ArrayList<>();

		int i = -1; // TCPpacketsIPUniques index counter
		int indexOfTCPUniques = 0;

		for (Packet packet: TCPpackets) {
			if (!TCPpacketsIPUniques.contains(packet.getSourceIP())) {
				TCPpacketsIPUniques.add(packet.getSourceIP());
				i++;
				TCPUniques.add(Utilities.filterBy(TCPpackets, "sourceIP", TCPpacketsIPUniques.get(i)).get(0));

				// Well-known services by port (sourcePort <= 1023)
				if (Integer.parseInt(TCPUniques.get(indexOfTCPUniques).getSourcePort()) <= 1023)
					reservedPorts.add(TCPUniques.get(indexOfTCPUniques));
				indexOfTCPUniques++;
			}
				
		}

		wellKnownServicesTCP = reservedPorts.size();
		
		return TCPpacketsIPUniques.size();
	}

	/**
	 * Q3 - How many TCP well known services.
	 * 
	 * @return number of TCP well known ports
	 */
	public int getWellKnownServicesTCP() {
		onlyTCP();
		return wellKnownServicesTCP;
	}
	
/*
******************************************
* QUESTAO 4
******************************************
*/
	
	/**
	 * Q4 - How many ICMP.
	 * 
	 * @return
	 */
	public int howManyICMP() {
        List<Packet> icmpV4 = Utilities.filterBy(packets, "protocol", "ICMP");
        List<Packet> icmpV6 = Utilities.filterBy(packets, "protocol", "ICMPv6");
		
        return icmpV4.size() + icmpV6.size();
	}
	
	/**
	 * Q4 - Gives the ICMP types.
	 * 
	 * @return ICMP types
	 */
	public Set<String> typesICMP() {
        List<Packet> icmpV4 = Utilities.filterBy(packets, "protocol", "ICMP");
		Set<String> types = new HashSet<String>();

        for (Packet packet : icmpV4) types.add(packet.getType());
        return types;
	}

/*
******************************************
* QUESTAO 5
******************************************
*/
	
	/**
	 * Q5 - Gives average size of all packets.
	 * 
	 * @return  average size of all packets
	 */
	public double averageSizePackets() {
		int size = 0;
		
		for(int i = 0; i < packets.size(); i++) {
			size += packets.get(i).getLength();
		}
		
		return size/packets.size();		
	}

	/**
	 * Q5 - Gives the size of the largest packet.
	 * 
	 * @return  size of the largest packet
	 */
	public double largestSizePackets() {
		Packet max = Collections.max(packets);
		
		return max.getLength();  
	}
	
	/**
	 * Q5 - Gives the size of the smallest packet.
	 * 
	 * @return  size of the smallest packet
	 */
	public double smallestSizePackets() {
		Packet min = Collections.min(packets);
		
		return min.getLength();  
	}

/*
******************************************
* QUESTAO 6
******************************************
*/
	
	/**
	 * Q6 - Gives the number of syn flags in the trace.
	 * 
	 * @return  number of syn flags
	 */
	public int howManySyn() {
		List<Packet> synPackets = Utilities.filterBy(packets, "flags", "0x002");

		return synPackets.size();
	}

	/**
	 * Q6 - Gives the IP that attempts to make a TCP connection the most.
	 * 
	 * @return	IP that sends the most SYN flags
	 */

	public String mostTCPAttemptsIP() {
		List<Packet> synPackets = Utilities.filterBy(packets, "flags", "0x002");
		HashMap<String, Integer> countSynByIP = new HashMap<>();

		for (Packet packet: synPackets) {
			if (!countSynByIP.containsKey(packet.getSourceIP()))
				countSynByIP.put(packet.getSourceIP(), 1);
			else 
				countSynByIP.put(packet.getSourceIP(), countSynByIP.get(packet.getSourceIP()) + 1);
		}

		return maxEntry(countSynByIP).getKey();
	}

	/**
	 * Gives the max entry.
	 * 
	 * @param countSynByIP 	the given HashMap
	 * 
	 * @return max entry of and Entry<String,Integer> 
	 */
	private Entry<String, Integer> maxEntry(HashMap<String, Integer> countSynByIP) {
		Entry<String, Integer> maxEntry = null;

		for (Entry<String, Integer> entry : countSynByIP.entrySet()) {
			if (maxEntry == null || entry.getValue().compareTo(maxEntry.getValue()) > 0)
				maxEntry = entry;
		}
		return maxEntry;
	}

/*
******************************************
* QUESTAO 7
******************************************
*/

	/**
	 * Auxiliar class to implement Q7.
	 * 
	 * Creates a pair of IPs including equals and hashCode methods implementation for this class.
	 */
    private class IPPair {
        private String ip1;
        private String ip2;

        private IPPair(String ip1, String ip2) {
            this.ip1 = ip1;
            this.ip2 = ip2;
        }

        private String getIp1() {return ip1;}

        private String getIp2() {return ip2;}

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof IPPair)) return false;
            IPPair other = (IPPair) o;
            return (ip1.equals(other.getIp1()) && ip2.equals(other.getIp2())) ||
                (ip1.equals(other.getIp2()) && ip2.equals(other.getIp1()));
        }

        /**
         * Overrides Object.hashCode implementing method from Joshua Bloch's "Effective Java".
         * 
         * @return This instance's hash code
         */
        @Override
        public int hashCode() {
            int code = ip1.hashCode();
            code = 31 * code + ip2.hashCode();
            return code;
        }
    }

	/**
	 * Q7 - How many TCP connections were made.
	 * 
	 * @return count of TCP connection
	 */ 
	public int howManyTCPconnections() {
		List<Packet> tcpPackets = Utilities.filterBy(packets, "protocol", "TCP");
        Set<IPPair> connections = new HashSet<>();

        for (Packet packet : tcpPackets) {
            IPPair ipPair = new IPPair(packet.getSourceIP(), packet.getDestIP());
            connections.add(ipPair);
        }

		return connections.size();
   }

/*
******************************************
* QUESTAO 8
******************************************
*/

   /** 
	* Q8 - Which IP receives the most packets.
	* 
	* @return IP that has received the most packets
    */
   public String getBiggestReceiverIP() {
        return biggestReceiverIP;
   }

   /**
	* Auxiliar method to find the biggest receiver (IP).
	* 
	* @return 
    */
   public void determineBiggestReceiver() {
		HashMap<String,Integer> received = new HashMap<String,Integer>();

		for (Packet packet : packets) {
			if (!received.containsKey(packet.getDestIP())) {
					received.put(packet.getDestIP(), packet.getLength());
			} else {
					received.put(packet.getDestIP(), received.get(packet.getDestIP()) + packet.getLength());
			}
		}
		
		biggestReceiverBytes = maxEntry(received).getValue(); 
        biggestReceiverIP = maxEntry(received).getKey();


   }

   /**
	* Q8 - How many bytes were received by the biggest receiver.
	* 
	* @return bytes received
    */
   public int biggestReceiverBytes() {
		return biggestReceiverBytes;
   }

   /**
	* Q8 - How many packets were received by the biggest receiver (IP).
	* 
	* @return number of received packets
    */
   public int biggestReceiverPackets() {
		List<Packet> receivedPackets = Utilities.filterBy(packets, "destIP", getBiggestReceiverIP());

		return receivedPackets.size();
	}

	/**
	 * Q8 - What is the throughput associated to the biggest receiver.
	 * 
	 * @return the throughput of the biggest receiver (IP)
	 */
    public Double biggestReceiverThroughput() {
        List<Packet> receivedPackets = 
            Utilities.filterBy(packets, "destIP", getBiggestReceiverIP());
        Double startingTime = Double.parseDouble(
            receivedPackets.
            get(0).
            getTime());
        Double finishTime = Double.parseDouble(
            receivedPackets.
            get(receivedPackets.size() - 1).
            getTime());
        
        return biggestReceiverBytes() / (finishTime - startingTime);
    }

/*
******************************************
* QUESTAO 9
******************************************
*/

	/**
	 * Q9 - Which IP sends the most packets.
	 * 
	 * @return
	 */
    public String getBiggestSenderIP() {
        return biggestSenderIP;
    }
	
	/**
	 * Q9 - Auxiliar method to find the biggest sender (IP).
	 * 
	 */
	public void determineBiggestSender() {
		HashMap<String,Integer> sent = new HashMap<String,Integer>();

		for (Packet packet : packets) {
			if (!sent.containsKey(packet.getSourceIP())) 
				sent.put(packet.getSourceIP(), packet.getLength());
			else 
				sent.put(packet.getSourceIP(), sent.get(packet.getSourceIP()) + packet.getLength());
		}

		biggestSenderBytes = maxEntry(sent).getValue();
        biggestSenderIP = maxEntry(sent).getKey();
	}

	/**
	 * Q9 - How many bytes were sent by the biggest sender.
	 * 
	 * @return bytes sent
	 */
	public int biggestSenderBytes() {
		return biggestSenderBytes;
   }

    /**
	* Q9 - How many packets were sent by the biggest sender (IP).
	* 
	* @return number of packets that were sent
    */
	public int biggestSenderPackets() {
		List<Packet> sentPackets = Utilities.filterBy(packets, "sourceIP", getBiggestSenderIP());

		return sentPackets.size();
	}

	/**
	 * Q9 - What is the throughput associated to the biggest sender.
	 * 
	 * @return the throughput of the biggest sender (IP)
	 */
    public Double biggestSenderThroughput() {
        List<Packet> sentPackets = 
            Utilities.filterBy(packets, "destIP", getBiggestSenderIP());
        Double startingTime = Double.parseDouble(
            sentPackets.
            get(0).
            getTime());
        Double finishTime = Double.parseDouble(
            sentPackets.
            get(sentPackets.size() - 1).
            getTime());
        
        return biggestSenderBytes() / (finishTime - startingTime);
    }

	public int fraction(int low, int high) {
		int fraction = 0;
		for (Packet packet : packets) {
			if (packet.getLength() > low && packet.getLength() <= high) fraction++;
		}

		return fraction;
	}
}  
