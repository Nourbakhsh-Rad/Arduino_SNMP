#if defined(ESP8266)
	#include <ESP8266WiFi.h> // ESP8266 Core WiFi Library         
#else
	#include <WiFi.h>        // ESP32 Core WiFi Library    
#endif

#include <WiFiUdp.h>

//#define UDP_TX_PACKET_MAX_SIZE 				484
//#define SNMP_PACKET_LENGTH 						1024
//#define SNMP_DEBUG 										0

#include <Arduino_SNMP.h>

const char* ssid = "SSID";
const char* password = "PASSWORD";

WiFiUDP udp;
SNMPAgent snmp = SNMPAgent("public");  // Starts an SMMPAgent instance with the community string 'public'

int changingNumber = 1;
int settableNumber = 0;

void setup(){
    Serial.begin(115200);
    WiFi.begin(ssid, password);
    Serial.println("");

    // Wait for connection
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.print("Connected to ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
    
    // give snmp a pointer to the UDP object
    snmp.setUDP(&udp);
    snmp.begin();
    
    // add 'callback' for an OID - pointer to an integer
    snmp.addIntegerHandler(".1.3.6.1.4.1.5.0", &changingNumber);
    
    // Using your favourite snmp tool:
    // snmpget -v 1 -c public <IP> 1.3.6.1.4.1.5.0
    
    // you can accept SET commands with a pointer to an integer (or string)
    snmp.addIntegerHandler(".1.3.6.1.4.1.5.1", &settableNumber, true);
    
    // snmpset -v 1 -c public <IP> 1.3.6.1.4.1.5.0 i 99
    
}

void loop(){
    snmp.loop(); // must be called as often as possible
    if(snmp.setOccurred){
        Serial.printf("Number has been set to value: %i", settableNumber);
        snmp.resetSetOccurred();
    }
    changingNumber++;
}