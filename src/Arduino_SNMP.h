#ifndef SNMPAgent_h
	#define SNMPAgent_h
	
	#ifndef UDP_TX_PACKET_MAX_SIZE
    #define UDP_TX_PACKET_MAX_SIZE 484
	#endif
	
	#ifndef SNMP_PACKET_LENGTH
		#if defined(ESP32)
			#define SNMP_PACKET_LENGTH 1500  // This will limit the size of packets which can be handled.
		#elif defined(ESP8266)
			#define SNMP_PACKET_LENGTH 512  // This will limit the size of packets which can be handled. ESP8266 is unstable and crashes as this value approaches or exceeds 1024. This appears to be a problem in the underlying WiFi or UDP implementation
		#else
			#define SNMP_PACKET_LENGTH 484  // This value may need to be made smaller for lower memory devices. This will limit the size of packets which can be handled.
		#endif
	#endif
	
	#ifndef SNMP_DEBUG
		#define SNMP_DEBUG 			0
	#endif
	
	#if	(SNMP_DEBUG)
		#define Snmp_Serial_print						Serial.print
		#define Snmp_Serial_println					Serial.println
		#define Snmp_Serial_printf					Serial.printf
	#else
		#define Snmp_Serial_print(...)
		#define Snmp_Serial_println(...)
		#define Snmp_Serial_printf(...)
	#endif
	
	#define MIN(X, Y) ((X < Y) ? X : Y)
	
	#include <UDP.h>
	
	#include "BER.h"
	#include "VarBinds.h"
	#include "SNMPRequest.h"
	#include "SNMPResponse.h"
	
	class ValueCallback {
	  public:
	    ValueCallback(ASN_TYPE atype): type(atype){};
	    char* OID;
	    ASN_TYPE type;
	    bool isSettable = false;
	    bool overwritePrefix = false;
	};
	
	class IntegerCallback: public ValueCallback {
	  public:
	    IntegerCallback(): ValueCallback(INTEGER){};
	    int* value;
	    bool isFloat = false;
	};
	
	class TimestampCallback: public ValueCallback {
	  public:
	    TimestampCallback(): ValueCallback(TIMESTAMP){};
	    int* value;
	};
	
	class StringCallback: public ValueCallback {
	  public:
	    StringCallback(): ValueCallback(STRING){};
	    char** value;
	};
	
	class OIDCallback: public ValueCallback {
	  public:
	    OIDCallback(): ValueCallback(ASN_TYPE::OID){};
	    char* value;
	};
	
	class Counter32Callback: public ValueCallback {
	  public:
	    Counter32Callback(): ValueCallback(ASN_TYPE::COUNTER32){};
	    uint32_t* value;
	};
	
	class Guage32Callback: public ValueCallback {
	  public:
	    Guage32Callback(): ValueCallback(ASN_TYPE::GUAGE32){};
	    uint32_t* value;
	};
	
	class Counter64Callback: public ValueCallback {
	  public:
	    Counter64Callback(): ValueCallback(ASN_TYPE::COUNTER64){};
	    uint64_t* value;
	};
	
	typedef struct ValueCallbackList {
	    ~ValueCallbackList(){
	        delete next;
	    }
	    ValueCallback* value;
	    struct ValueCallbackList* next = 0;
	} ValueCallbacks;
	
	#define RFC1213_OID_sysDescr						(char*)(".1.3.6.1.2.1.1.1.0")
	#define RFC1213_OID_sysObjectID				 	(char*)(".1.3.6.1.2.1.1.2.0")
	#define RFC1213_OID_sysUpTime					 	(char*)(".1.3.6.1.2.1.1.3.0")
	#define RFC1213_OID_sysContact				 	(char*)(".1.3.6.1.2.1.1.4.0")
	#define RFC1213_OID_sysName						 	(char*)(".1.3.6.1.2.1.1.5.0")
	#define RFC1213_OID_sysLocation				 	(char*)(".1.3.6.1.2.1.1.6.0")
	#define RFC1213_OID_sysServices				 	(char*)(".1.3.6.1.2.1.1.7.0")
	
	typedef struct RFC1213SystemStruct
	{
	    char* 			sysDescr;						/* .1.3.6.1.2.1.1.1.0 */
	    char* 			sysObjectID;				/* .1.3.6.1.2.1.1.2.0 */
	    uint32_t 		sysUpTime;					/* .1.3.6.1.2.1.1.3.0 */
	    char* 			sysContact;					/* .1.3.6.1.2.1.1.4.0 */
	    char*				sysName;						/* .1.3.6.1.2.1.1.5.0 */
	    char* 			sysLocation;				/* .1.3.6.1.2.1.1.6.0 */
	    int32_t			sysServices;				/* .1.3.6.1.2.1.1.7.0 */
	} RFC1213_list;
	
	typedef enum 
	{
	     SNMP_PERM_NONE,
	     SNMP_PERM_READ_ONLY,
	     SNMP_PERM_READ_WRITE
	} SNMP_PERMISSION;
	
	#include "SNMPTrap.h"
	
	class SNMPAgent {
	    public:
	        SNMPAgent(){};
	        SNMPAgent(const char* community): _community(community){};
	
	        void setRWCommunity(const char* readWrite){       // read/write
	            this->_community = readWrite;
	        }
	
	        void setROCommunity(const char* readOnly){       // read/write
	            this->_readOnlyCommunity = readOnly;
	        }
	
	        void setCommunity(const char* readOnly, const char* readWrite){    // readOnly, read/write
	            this->_community = readWrite;
	            this->_readOnlyCommunity = readOnly;
	        }
	        
	        const char* _community;
	        const char* _readOnlyCommunity = 0;
	
	
	        ValueCallbacks* callbacks = new ValueCallbacks();
	        ValueCallbacks* callbacksCursor = callbacks;
	//      bool addHandler(char* OID, SNMPOIDResponse (*callback)(SNMPOIDResponse* response, char* oid));
	        ValueCallback* findCallback(char* oid, bool next = false);
	        ValueCallback* addFloatHandler(char* oid, float* value, bool isSettable = false, bool overwritePrefix = false); // this obv just adds integer but with the *0.1 set
	        ValueCallback* addStringHandler(char*, char**, bool isSettable = false, bool overwritePrefix = false); // passing in a pointer to a char* 
	        ValueCallback* addIntegerHandler(char* oid, int* value, bool isSettable = false, bool overwritePrefix = false);
	        ValueCallback* addTimestampHandler(char* oid, int* value, bool isSettable = false, bool overwritePrefix = false);
	        ValueCallback* addOIDHandler(char* oid, char* value, bool overwritePrefix = false);
	        ValueCallback* addCounter64Handler(char* oid, uint64_t* value, bool overwritePrefix = false);
	        ValueCallback* addCounter32Handler(char* oid, uint32_t* value, bool overwritePrefix = false);
	        ValueCallback* addGuageHandler(char* oid, uint32_t* value, bool overwritePrefix);
	
	        void setUDP(UDP* udp);
	        bool begin(uint16_t port = 161);
	        bool begin(char*, uint16_t port = 161);
	        void stop();
	        bool loop();
	        char oidPrefix[40];
	        char OIDBuf[MAX_OID_LENGTH];
	        bool setOccurred = false;
	        void resetSetOccurred()
	        {
	            setOccurred = false;
	        }
	        
	        UDP* _udp;
	        bool removeHandler(ValueCallback* callback);
	        void addHandler(ValueCallback* callback);
	        bool sortHandlers();
	        
	        void swap(ValueCallbacks*, ValueCallbacks*);
	        
	        // automatically enables and adds RFC1213 "System" variables. provide a 
	        void enableRFC1213()
	        { 
						/////
	        }
	        
	    private:
	        bool sort_oid(char*, char*);
	        unsigned char _packetBuffer[SNMP_PACKET_LENGTH*3];
	        bool inline receivePacket(int length);
	        
	        bool parsePacket(int len);
	    		void printPacket(int len);
	    		
	        SNMPOIDResponse* generateErrorResponse(ERROR_STATUS error, char* oid)
	        {
	            SNMPOIDResponse* errorResponse = new SNMPOIDResponse();
	            errorResponse->oid = new OIDType(oid);
	            errorResponse->errorStatus = error;
	            errorResponse->value = new NullType();
	            errorResponse->type = NULLTYPE;
	            return errorResponse;
	        }
	};
	
	void SNMPAgent::setUDP(UDP* udp)
	{
	    if(_udp){
	        _udp->stop();
	    }
	    _udp = udp;
	}
	
	bool SNMPAgent::begin(uint16_t port)
	{
	    if(!_udp) return false;
	    _udp->begin(port);
	    return true;
	}
	
	bool SNMPAgent::begin(char* prefix, uint16_t port)
	{
	    strncpy(oidPrefix, prefix, 40);
	    return this->begin(port);
	}
	
	void SNMPAgent::stop()
	{
	    if(_udp)
	    {
	        _udp->stop();
	    }
	    _udp = 0;
	}
	
	bool SNMPAgent::loop()
	{
	    if(!_udp)
	    {
	        return false;
	    }
	    return receivePacket(_udp->parsePacket());
	}
	
	void SNMPAgent::printPacket(int len)
	{
		#if (SNMP_DEBUG ==1)
	    Snmp_Serial_print(F("[DEBUG SNMP] packet: "));
	    for (int i = 0; i < len; i++)
	    {
	        Snmp_Serial_printf("%02x ", _packetBuffer[i]);
	    }
	    Snmp_Serial_println();
	  #endif
	}
	
	bool inline SNMPAgent::receivePacket(int packetLength)
	{
	   if(!packetLength) 		return false;
	   
	   Snmp_Serial_print(F("[DEBUG SNMP] Packet Length: "));
	   Snmp_Serial_print(packetLength);
	   Snmp_Serial_print(F("  From Address: "));
	   Snmp_Serial_println(_udp->remoteIP());
	   
	   if(packetLength < 0 || packetLength > SNMP_PACKET_LENGTH){
	       Snmp_Serial_println(F("[DEBUG SNMP] dropping packet"));
	       return false;
	   }
	   
	    memset(_packetBuffer, 0, SNMP_PACKET_LENGTH*3);
	    int len = packetLength;
	    _udp->read(_packetBuffer, MIN(len, SNMP_PACKET_LENGTH));
	    _udp->flush();
	    _packetBuffer[len] = 0;		// null terminate the buffer
	    
	    printPacket(len);
			
	    return parsePacket(len);
	}
	
	bool SNMPAgent::parsePacket(int len)
	{
	    SNMPRequest* snmprequest = new SNMPRequest();
	    if(snmprequest->parseFrom(_packetBuffer)){
	       
	        // check version and community
	        SNMP_PERMISSION requestPermission = SNMP_PERM_NONE;
	
	        if(_readOnlyCommunity != 0 && strcmp(_readOnlyCommunity, snmprequest->communityString) == 0) { // snmprequest->version != 1
	            requestPermission = SNMP_PERM_READ_ONLY;
	        }
	
	        if(strcmp(_community, snmprequest->communityString) == 0) { // snmprequest->version != 1
	            requestPermission = SNMP_PERM_READ_WRITE;
	        }
	
	        if(requestPermission == SNMP_PERM_NONE){
	            Snmp_Serial_println(F("[DEBUG SNMP] Invalid permissions"));
	            delete snmprequest;
	            return false;
	        }
	        
	        SNMPResponse* response = new SNMPResponse();
	        
	        response->requestID = snmprequest->requestID;
	        response->version = snmprequest->version - 1;
	        strncpy(response->communityString, snmprequest->communityString, 15);
	        
	        int varBindIndex = 1;
	        snmprequest->varBindsCursor = snmprequest->varBinds;
	        while(true){
	            Snmp_Serial_print(F("[DEBUG SNMP] OID: "));    Snmp_Serial_print(snmprequest->varBindsCursor->value->oid->_value);
	        		Snmp_Serial_print(F("  Version: "));		Snmp_Serial_println(snmprequest->version -1);
	            
	            // Deal with OID request here:
	            bool walk = false;
	            if(snmprequest->requestType == GetNextRequestPDU){
	                walk = true;
	            }
	            
	            ValueCallback* callback = findCallback(snmprequest->varBindsCursor->value->oid->_value, walk);
	            if(callback){ // this is where we deal with the response varbind
	                SNMPOIDResponse* OIDResponse = new SNMPOIDResponse();
	                OIDResponse->errorStatus = (ERROR_STATUS)0;
	                
	                memset(OIDBuf, 0, MAX_OID_LENGTH);
	                if(!callback->overwritePrefix){
	                    strcat(OIDBuf, oidPrefix);
	                }
	                
	                strcat(OIDBuf, callback->OID);
	                
	                OIDResponse->oid = new OIDType(OIDBuf);
	                OIDResponse->type = callback->type;
	                
	                // TODO: this whole thing needs better flow: proper checking for errors etc.
	                
	                if(snmprequest->requestType == SetRequestPDU){
	                    // settable data..
	                    if(callback->isSettable){
	                        if(requestPermission == SNMP_PERM_READ_ONLY){ // community is readOnly
	                            Snmp_Serial_println(F("[DEBUG SNMP] READONLY COMMUNITY USED")); 
	                            SNMPOIDResponse* errorResponse = generateErrorResponse(NO_ACCESS, snmprequest->varBindsCursor->value->oid->_value);
	
	                            
	                        	response->addErrorResponse(errorResponse, varBindIndex);
	                        } else {
	                            if(callback->type != snmprequest->varBindsCursor->value->type){
	                                // wrong data type to set..
	                                // BAD_VALUE
	                                Snmp_Serial_println(F("[DEBUG SNMP] VALUE-TYPE DOES NOT MATCH")); 
	                                SNMPOIDResponse* errorResponse = generateErrorResponse(BAD_VALUE, snmprequest->varBindsCursor->value->oid->_value);
	                        
	                        	response->addErrorResponse(errorResponse, varBindIndex);
	                            } else {
	                                // actually set it
	                                switch(callback->type){
	                                    case STRING:
	                                        {
	                                            /* SHN */
	                                            //memcpy(*((StringCallback*)callback)->value, String(((OctetType*)snmprequest->varBindsCursor->value->value)->_value).c_str(), 32);// FIXME: this is VERY dangerous, i'm assuming the length of the source char*, this needs to change. for some reason strncpy didnd't work, need to look into this. the '25' also needs to be defined somewhere so this won't break;
	                                            //*(*((StringCallback*)callback)->value + 31) = 0x0; // close off the dest string, temporary
	                                            //OctetType* value = new OctetType(*((StringCallback*)callback)->value);
	                                            //OIDResponse->value = value;
	                                            strncpy(*((StringCallback *)callback)->value, String(((OctetType*)snmprequest->varBindsCursor->value->value)->_value).c_str(), strlen(((OctetType*)snmprequest->varBindsCursor->value->value)->_value));
	                                            OctetType* value = new OctetType(*((StringCallback*)callback)->value);
	                                            OIDResponse->value = value;
	                                            setOccurred = true;
	                                        }
	                                    break;
	                                    case INTEGER:
	                                        {
	                                            IntegerType* value = new IntegerType();
	                                            if(!((IntegerCallback*)callback)->isFloat){
	                                                *(((IntegerCallback*)callback)->value) = ((IntegerType*)snmprequest->varBindsCursor->value->value)->_value;
	                                                value->_value = *(((IntegerCallback*)callback)->value);
	                                            } else {
	                                                *(((IntegerCallback*)callback)->value) = (float)(((IntegerType*)snmprequest->varBindsCursor->value->value)->_value / 10);
	                                                value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
	                                            }
	                                            OIDResponse->value = value;
	                                            setOccurred = true;
	                                        }
	                                    break;
	                                }
	                                	response->addResponse(OIDResponse);
	                                
	                            }
	                        }
	                    } else {
	                        // not settable, send error
	                        Snmp_Serial_println(F("[DEBUG SNMP] OID NOT SETTABLE")); 
	                        SNMPOIDResponse* errorResponse = generateErrorResponse(READ_ONLY, snmprequest->varBindsCursor->value->oid->_value);
	                        
	                        	response->addErrorResponse(errorResponse, varBindIndex);
												}
	                } else if(snmprequest->requestType == GetRequestPDU || snmprequest->requestType == GetNextRequestPDU){
	                
	                    if(callback->type == INTEGER){
	                        IntegerType* value = new IntegerType();
	                        if(!((IntegerCallback*)callback)->isFloat){
	                            value->_value = *(((IntegerCallback*)callback)->value);
	                        } else {
	                            value->_value = *(float*)(((IntegerCallback*)callback)->value) * 10;
	                        }
	                        OIDResponse->value = value;
	                    } else if(callback->type == STRING){
	                        OctetType* value = new OctetType(*((StringCallback*)callback)->value);
	                        OIDResponse->value = value;
	                    } else if(callback->type == TIMESTAMP){
	                        TimestampType* value = new TimestampType(*(((TimestampCallback*)callback)->value));
	                        OIDResponse->value = value;
	                    } else if(callback->type == OID){
	                        OIDType* value = new OIDType((((OIDCallback*)callback)->value));
	                        OIDResponse->value = value;
	                    } else if(callback->type == COUNTER64){
	                        Counter64* value = new Counter64(*((Counter64Callback*)callback)->value);
	                        OIDResponse->value = value;
	                    } else if(callback->type == COUNTER32){
	                        Counter32* value = new Counter32(*((Counter32Callback*)callback)->value);
	                        OIDResponse->value = value;
	                    } else if(callback->type == GUAGE32){
	                        Guage* value = new Guage(*((Guage32Callback*)callback)->value);
	                        OIDResponse->value = value;
	                    }
	                    
	                    ///////////////
	                    response->addResponse(OIDResponse);
	                }
	            } else {
	                // inject a NoSuchObject error
	                Snmp_Serial_println(F("[DEBUG SNMP] OID NOT FOUND")); 
	                SNMPOIDResponse* errorResponse = generateErrorResponse(NO_SUCH_NAME, snmprequest->varBindsCursor->value->oid->_value);
	                
	                 	response->addErrorResponse(errorResponse, varBindIndex);
	            }
	            
	            // -------------------------
	            snmprequest->varBindsCursor = snmprequest->varBindsCursor->next;
	            if(!snmprequest->varBindsCursor->value){
	                break;
	            }
	            varBindIndex++;
	        }
	//        Snmp_Serial_println(F("[DEBUG SNMP] Sending UDP"));
	        memset(_packetBuffer, 0, SNMP_PACKET_LENGTH*3);
	        int length = response->serialise(_packetBuffer);
	        if(length <= SNMP_PACKET_LENGTH*2){
	        	Snmp_Serial_print(F("[DEBUG SNMP] Send packet to IP: "));		Snmp_Serial_print(_udp->remoteIP());
	        	Snmp_Serial_print(F("  Port: "));		Snmp_Serial_println(_udp->remotePort());
	        	
	            _udp->beginPacket(_udp->remoteIP(), _udp->remotePort());
	            _udp->write(_packetBuffer, length);
	            if(!_udp->endPacket()){
	                Snmp_Serial_println(F("[DEBUG SNMP] COULDN'T SEND PACKET"));
	                for(int i = 0;  i < length; i++){
	                    Snmp_Serial_print(_packetBuffer[i], HEX);
	                }
	                Snmp_Serial_println();
	                Snmp_Serial_print(F("[DEBUG SNMP] Length: "));		Snmp_Serial_println(length);
	                Snmp_Serial_print(F("[DEBUG SNMP] Length of incoming: "));		Snmp_Serial_println(len);
	            }
	        } else {
	            Snmp_Serial_println(F("[DEBUG SNMP] dropping packet"));
	        }
	        
	        delete response;
	    } else {
	        Snmp_Serial_println(F("[DEBUG SNMP] CORRUPT PACKET"));
	        VarBindList* tempList = snmprequest->varBinds;
	        if(tempList){
	            while(tempList->next){
	                delete tempList->value->oid;
	                delete tempList->value->value;
	                tempList = tempList->next;
	            }
	            delete tempList->value->oid;
	            delete tempList->value->value;
	        }
	    }
	    delete snmprequest;
	
			//Snmp_Serial_printf("[DEBUG SNMP] Current heap size: %u\n", ESP.getFreeHeap());
	    return true;
	}
	
	ValueCallback* SNMPAgent::findCallback(char* oid, bool next)
	{
	    bool useNext = false;
	    callbacksCursor = callbacks;
	    
	    if(callbacksCursor->value){
	        while(true){
	            if(!useNext){
	                memset(OIDBuf, 0, MAX_OID_LENGTH);
	                if(!callbacksCursor->value->overwritePrefix){
	                    strcat(OIDBuf, oidPrefix);
	                }
	                strcat(OIDBuf, callbacksCursor->value->OID);
	                if(strcmp(OIDBuf, oid) == 0){
	                    //  found
	                    if(next){
	                        useNext = true;
	                    } else {
	                        return callbacksCursor->value;
	                    }
	                } else if(next){
	                    // doesn't match, lets do a strstr to find out if it's possible for a walk
	                    if(strstr(OIDBuf, oid)){ // this is the first occurance of the ENTIRE requested OID, which means it's the start of a walk, lets start here
	                        return callbacksCursor->value;
	                    }
	                }
	            } else {
	                return callbacksCursor->value;
	            }
	            
	            if(callbacksCursor->next){
	                callbacksCursor = callbacksCursor->next;
	            } else {
	                break;
	            }
	        }
	    }
	    
	    return 0;
	}
	
	ValueCallback* SNMPAgent::addStringHandler(char* oid, char** value, bool isSettable, bool overwritePrefix)
	{
	    ValueCallback* callback = new StringCallback();
	    callback->overwritePrefix = overwritePrefix;
	    if(isSettable) callback->isSettable = true;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((StringCallback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addIntegerHandler(char* oid, int* value, bool isSettable, bool overwritePrefix)
	{
	    ValueCallback* callback = new IntegerCallback();
	    callback->overwritePrefix = overwritePrefix;
	    if(isSettable) callback->isSettable = true;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((IntegerCallback*)callback)->value = value;
	    ((IntegerCallback*)callback)->isFloat = false;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addFloatHandler(char* oid, float* value, bool isSettable, bool overwritePrefix)
	{
	    ValueCallback* callback = new IntegerCallback();
	    callback->overwritePrefix = overwritePrefix;
	    if(isSettable) callback->isSettable = true;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((IntegerCallback*)callback)->value = (int*)value;
	    ((IntegerCallback*)callback)->isFloat = true;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addTimestampHandler(char* oid, int* value, bool isSettable, bool overwritePrefix)
	{
	    ValueCallback* callback = new TimestampCallback();
	    callback->overwritePrefix = overwritePrefix;
	    if(isSettable) callback->isSettable = true;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((TimestampCallback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addOIDHandler(char* oid, char* value, bool overwritePrefix)
	{
	    ValueCallback* callback = new OIDCallback();
	    callback->overwritePrefix = overwritePrefix;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((OIDCallback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addCounter64Handler(char* oid, uint64_t* value, bool overwritePrefix)
	{
	    ValueCallback* callback = new Counter64Callback();
	    callback->overwritePrefix = overwritePrefix;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((Counter64Callback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addCounter32Handler(char* oid, uint32_t* value, bool overwritePrefix)
	{
	    ValueCallback* callback = new Counter32Callback();
	    callback->overwritePrefix = overwritePrefix;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((Counter32Callback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	ValueCallback* SNMPAgent::addGuageHandler(char* oid, uint32_t* value, bool overwritePrefix)
	{
	    ValueCallback* callback = new Guage32Callback();
	    callback->overwritePrefix = overwritePrefix;
	    callback->OID = (char*)malloc((sizeof(char) * strlen(oid)) + 1);
	    strcpy(callback->OID, oid);
	    ((Guage32Callback*)callback)->value = value;
	    addHandler(callback);
	    return callback;
	}
	
	void SNMPAgent::addHandler(ValueCallback* callback)
	{
	    callbacksCursor = callbacks;
	    if(callbacksCursor->value){
	        while(callbacksCursor->next != 0){
	            callbacksCursor = callbacksCursor->next;
	        }
	        callbacksCursor->next = new ValueCallbacks();
	        callbacksCursor = callbacksCursor->next;
	        callbacksCursor->value = callback;
	        callbacksCursor->next = 0;
	    } else 
	        callbacks->value = callback;
	}
	
	// Let's implement this properly, we also want to inntroduce a sort() so after we add or remove stuff around we can make sure snmpwalk will still erturn in an expected way.
	
	bool SNMPAgent::removeHandler(ValueCallback* callback)			// this will remove the callback from the list and shift everything in the list back so there are no gaps, this will not delete the actual callback
	{
	    callbacksCursor = callbacks;
	    // Snmp_Serial_println(F("[DEBUG SNMP] Entering hell..."));
	    if(!callbacksCursor->value){
	            return false;
	    }
	    bool shifting = false;
	    if(callbacksCursor->value == callback){ // first callback is it
	        shifting = true;
	        callbacks = callbacksCursor->next; // save next element to the current global cursor
	    } else {
	        while(callbacksCursor->next != 0){
	            if(callbacksCursor->next->value == callback){ // if the thing pouinted to by NEXT is the thing we want to remove
	                if(callbacksCursor->next->next != 0){ // if next has a next that we replace the first next by
	                    callbacksCursor->next = callbacksCursor->next->next;
	                } else {
	                    callbacksCursor->next = 0;
	                }
	                shifting = true;
	                break;
	            }
	            callbacksCursor = callbacksCursor->next;
	        }
	    }
	    
	    return shifting;
	}
	
	bool SNMPAgent::sortHandlers() 		// we want to sort our callbacks in order of OID's so we can walk correctly
	{
	    callbacksCursor = callbacks;
	    
	    int swapped, i;
	    ValueCallbacks* ptr1;
	    ValueCallbacks* lptr = 0;
	 
	    /* Checking for empty list */
	    if (callbacksCursor == 0)       return false;
	 		
	    do
	    {
	        swapped = 0;
	        ptr1 = callbacksCursor;
	 
	        while (ptr1->next != lptr)
	        {
	            char OID1[MAX_OID_LENGTH] = {0};
	            char OID2[MAX_OID_LENGTH] = {0};
	
	            if(!ptr1->value->overwritePrefix){
	                strcat(OID1, oidPrefix);
	            }
	            strcat(OID1, ptr1->value->OID);
	
	
	            if(!ptr1->next->value->overwritePrefix){
	                strcat(OID2, oidPrefix);
	            }
	            strcat(OID2, ptr1->next->value->OID);
	
	
	            if (!sort_oid(OID1, OID2))
	            { 
	                swap(ptr1, ptr1->next);
	                swapped = 1;
	            }
	            ptr1 = ptr1->next;
	        }
	        lptr = ptr1;
	    }
	    while (swapped);
	    return true;
	}
	
	void SNMPAgent::swap(ValueCallbacks* one, ValueCallbacks* two)
	{
	    ValueCallback* temp = one->value;
	    one->value = two->value;
	    two->value = temp; 
	}
	
	bool SNMPAgent::sort_oid(char* oid1, char* oid2)		 // returns true if oid1 EARLIER than oid2
	{
	    uint16_t oid_nums_1[MAX_OID_LENGTH] = {0}; // max 40 deep
	    uint16_t oid_nums_2[MAX_OID_LENGTH] = {0}; // max 40 deep
	
	    int i = 0; // current num_array index
	    bool toBreak = false;
	    
	    while(*oid1){
	        if(*oid1 == '.') oid1++;
	        int num = 0;
	        if(sscanf(oid1, "%d", &num)){
	            // worked?
	            oid_nums_1[i++] = num;
	            while(*oid1 != '.') {
	                if(*oid1 == 0){
	                    toBreak = true;
	                    break;
	                }
	                oid1++;
	            }
	            if(toBreak) break;
	        } else {
	            // break
	            break;
	        }
	    }
	
	    i = 0; // current num_array index
	    toBreak = false;
	    
	    while(*oid2){
	        if(*oid2 == '.') oid2++;
	        int num = 0;
	        if(sscanf(oid2, "%d", &num)){
	            // worked?
	            oid_nums_2[i++] = num;
	            while(*oid2 != '.') {
	                if(*oid2 == 0){
	                    toBreak = true;
	                    break;
	                }
	                oid2++;
	            }
	            if(toBreak) break;
	        } else {
	            // break
	            break;
	        }
	    }
			
	    for(int j = 0; j < i; j++){
	        if(oid_nums_1[j] != oid_nums_2[j]){ // if they're the same then we're on same levvel
	            if(oid_nums_1[j] < oid_nums_2[j]){ // if this level is smaller, then we are earlier. this will also work if this oid is a parent of the other oid because by default we'll be 0
	                return true;
	            } else {
	                return false;
	            }
	        }
	    }
	    
	    return true;
	}
	
#endif
