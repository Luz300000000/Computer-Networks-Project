import java.io.FileNotFoundException;
import java.util.Scanner;

public class TestMP2 {

	public static void main(String[] args) throws FileNotFoundException {
		TrafficAnalysis analiser = new TrafficAnalysis("traceA.csv");
			
		Scanner stdin = new Scanner(System.in);
		printMenu(menuOptions);
		int option = stdin.nextInt();
		
		switch(option) {
			case 0:
				break;
	
		// Q1
			// numero de pacotes que possuem emissor e recetor IPv4
			case 1: 
				System.out.println(analiser.packetsInIPv4());
				break;
			
			// numero de pacotes que possuem emissor e recetor IPv6
			case 2:	
				System.out.println(analiser.packetsInIPv6());
				break;
			
			// numero dos pacotes que possuem emissor e recetor hostnames
			case 3:	
				System.out.println(analiser.packetsWithIPHostName());
				break;	
				
		// Q2
			// duracao total do trace
			case 4:
				System.out.println(analiser.time());
				break;
			
			// numero de pacotes no trace
			case 5:
				System.out.println(analiser.howManyPackets());
				break;
				
		// Q3	
			// quantos portos TCP de origem unica 
			case 6:
				System.out.println(analiser.onlyTCP());
				break;
	
			// quais deles sao principais servicos de rede conhecidos (HTTP, FTP, DNS)
			case 7:
				System.out.println(analiser.getWellKnownServicesTCP());
				break;
		
		// Q4
			// numero de pacotes ICMP na trace
			case 8:
				System.out.println(analiser.howManyICMP());
				break;
				
			// tipos de pacotes ICMP
			case 9:
				System.out.println(analiser.typesICMP().toString());
				break;
			
		// Q5		
			// tamanho medio dos pacotes	
			case 10:
				System.out.println(analiser.averageSizePackets());
				break;
		
			// packet com maior tamanho
			case 11: 
				System.out.println(analiser.largestSizePackets());
				break;
				
			// packet com menor tamanho
			case 12: 
				System.out.println(analiser.smallestSizePackets());
				break;
				
		// Q6		
			// quantas tentativas de conexao(pacote syn)
			case 13: 
				System.out.println(analiser.howManySyn());
				break;
				
			// endereco IP que fez mais tentativas	
			case 14: 
				System.out.println(analiser.mostTCPAttemptsIP());
				break;
				
		// Q7	
			// quantas ligacoes TCP no trace
			case 15:
				System.out.println(analiser.howManyTCPconnections());
				break;
		
		// Q8
			// endereco IP recetor que recebe maior fracao de trafego
			case 16:
				System.out.println(analiser.getBiggestReceiverIP());
				break;
				
			// quantos bytes o endereco IP recetor que recebe maior fracao de trafego recebe
			case 17:
				System.out.println( analiser.biggestReceiverBytes()  );
				break;
				
			// quantos pacotes o endereco IP recetor que recebe maior fracao de trafego recebe
			case 18:
				System.out.println( analiser.biggestReceiverPackets()  );
				break;
				
			// qual e o debito do endereco IP recetor que recebe maior fracao de trafego 
			case 19:
				System.out.println(analiser.biggestReceiverThroughput());
				break;
				
		// Q9
			// endereco IP emissor que envia maior fracao de trafego
			case 20:
				System.out.println(analiser.getBiggestSenderIP());
				break;
				
			// quantos bytes o endereco IP envia que recebe maior fracao de trafego recebe
			case 21:
				System.out.println( analiser.biggestSenderBytes()  );
				break;
				
			// quantos pacotes o endereco IP que envia maior fracao de trafego recebe
			case 22:
				System.out.println( analiser.biggestSenderPackets()  );
				break;
					
			// qual e o debito do endereco IP que envia maior fracao de trafego 
			case 23:
				System.out.println(analiser.biggestSenderThroughput());
				break;
		}
		
		stdin.close();
	}
	
    private static String[] menuOptions = {
    		"0- sair",
    		"1- numero de pacotes que possuem emissor e recetor IPv4",
    		"2- numero de pacotes que possuem emissor e recetor IPv6",
    		"3- numero dos que possuem emissor e recetor hostnames",
            "4- duracao total dos traces",
            "5- qual eh o numero de pacotes contidos",
            "6- Quantos portos TCP de origem unicos apareceram no trace?",
            "7- quantos portos TCP correspondem aos principais servicos de rede conhecidos (HTTP, FTP, DNS, etc)",
            "8- Qual eh o numero de pacotes ICMP contidos no trace?",
            "9- quais sao os tipos de pacotes ICMP",
            "10- tamanho medio dos pacotes no trace",
            "11- tamanho maximo dos pacotes no trace",
            "12- tamanho minimo dos pacotes no trace",
            "13- o envio de um pacote SYN representa uma tentativa de estabelecer uma ligacao TCP, indique quantas dessas tentativas aparecem no trace",
            "14- Indique qual eh o endereco IP que fez mais tentativas deste tipo",
            "15- quantas ligacoes TCP existem no trace?",
            "16- endereco IP que recebe maior fracao de trafego",
            "17- quantos bytes o endereco IP que recebe maior fracao de trafego recebe",
            "18- quantos pacotes o endereco IP que recebe maior fracao de trafego recebe",
            "19- qual e o debito do endereco IP que recebe maior fracao de trafego ",
            "20- endereco IP emissor que envia maior fracao de trafego",
            "21- quantos bytes o endereco IP envia que recebe maior fracao de trafego recebe",
            "22- quantos pacotes o endereco IP que envia maior fracao de trafego recebe",
            "23- qual e o debito do endereco IP que envia maior fracao de trafego "
    };
    
    public static void printMenu(String[] options){
    	
        for (String option : options){
        	System.out.println(option);
        }
        
        System.out.print("Escolhe a opcao : ");
    }
}
