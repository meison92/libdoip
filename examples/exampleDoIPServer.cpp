#include "DoIPServer.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <string>

using namespace std;

static const unsigned short LOGICAL_ADDRESS = 0x22b8;

DoIPServer server;
unique_ptr<DoIPConnection> connection(nullptr);
std::vector<std::thread> doipReceiver;
bool serverActive = false;
FILE* fp_ = nullptr;

struct FileTransferAddFile {
  std::string filePathAndName;
  uint32_t compressionMethod;
  uint32_t encryptingMethod;
  uint64_t fileSizeUncompressed;
  uint64_t fileSizeCompressed;
};

bool DeserializeFileTransferAddFile(
  uint16_t filePathAndNameLength,
  unsigned char* fileInfomation, int length,
  FileTransferAddFile& result) {

  if (length < filePathAndNameLength + 2) {
    return false;
  }

  result.filePathAndName = std::string(
    (char*)fileInfomation,
    filePathAndNameLength);

  size_t index = filePathAndNameLength;
  uint8_t dataFormatIdentifier = fileInfomation[index++];
  uint8_t fileSizeParameterLength = fileInfomation[index++];
  result.compressionMethod = dataFormatIdentifier & 0xf0;
  result.encryptingMethod = dataFormatIdentifier & 0xf;

  result.fileSizeUncompressed = 0;
  result.fileSizeCompressed = 0;

  if (length < filePathAndNameLength + 2 + fileSizeParameterLength * 2) {
    return false;
  }

  if (fileSizeParameterLength > 8) {
    return false;
  }

  for (int i = 0; i < fileSizeParameterLength; i++) {
    result.fileSizeUncompressed |= (fileInfomation[index++] << ((fileSizeParameterLength - i - 1) * 8));
  }

  for (int i = 0; i < fileSizeParameterLength; i++) {
    result.fileSizeCompressed |= (fileInfomation[index++] << ((fileSizeParameterLength - i - 1) * 8));
  }

  return true;
}

/**
 * Is called when the doip library receives a diagnostic message.
 * @param address   logical address of the ecu
 * @param data      message which was received
 * @param length    length of the message
 */
void ReceiveFromLibrary(unsigned short sourceaddress, unsigned short targetaddress, unsigned char* data, int length) {
    cout << "---> DoIPMessages received from [0x" << std::hex << std::setw(4) << std::setfill('0') << sourceaddress << 
                                    "] to [0x" << std::hex << std::setw(4) << std::setfill('0') << targetaddress << "] : ";
    for(int i = 0; i < (length>30 ? 30 : length); i++) {
        cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    cout << endl;

    static uint32_t dataRecord = 0;

    if(length > 2 && data[0] == 0x22)  {
        uint16_t dataId = ((uint16_t)data[1] << 8) | data[2];
        cout << "Read the dataId " << (uint32_t)dataId << ", dataRecord=" << dataRecord << endl;
        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1], data[2], (uint8_t)(dataRecord >> 24 && 0xFF),
                                                                                      (uint8_t)(dataRecord >> 16 && 0xFF),
                                                                                      (uint8_t)(dataRecord >> 8 && 0xFF),
                                                                                      (uint8_t)(dataRecord && 0xFF)};
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(length > 2 && data[0] == 0x2E)  {
        uint16_t dataId = ((uint16_t)data[1] << 8) | data[2];
        for (int i =3; i<6; i++)
        {
            dataRecord = ((uint16_t)data[i] << 8) | data[i+1];;
        }
        cout << "Write the dataId " << (uint32_t)dataId << ", dataRecord=" << dataRecord << endl;
        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1] };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(length == 2 && data[0] == 0x10)  {
        // P2Service_Max = 50ms, P2StartService_Max = 500ms
        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1], 0x00, 0x32, 0x01, 0xf4 };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(data[0] == 0x27)  {
        static int security_Level;
        // request seed
        if (length == 2 &&  data[1] <= 0x41 && data[1]%2==1)
        {
            security_Level = data[1]*2 -1;
            cout << "SecurityAccess RequestSeed: SecurityLevel = " << std::dec << security_Level << endl;
            unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1], 
                                            (uint8_t)(data[1] + 0x10),
                                            (uint8_t)(data[1] + 0x11),
                                            (uint8_t)(data[1] + 0x12),
                                            (uint8_t)(data[1] + 0x13) };
            connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
        }
        // send key
        if (length > 2 &&  data[1] <= 0x42 && data[1]%2==0)
        {
            cout << "SecurityAccess SendKey: SecurityLevel = " << std::dec << (data[1]-1)*2 -1 << endl;
            unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1]};
            connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
        }
    }
    else if(length == 2 && data[0] == 0x3E)  {
        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1] };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(length > 2 && data[0] == 0x36)  {
        cout << "-> Send 0x36 message positive response" << endl;

        if(fp_){
            auto size = fwrite(data+2,
                1, length - 2 , fp_);
            if(size != (size_t)(length - 2)){
                //neg ack
                connection->sendNegativeAck(0x04);
                return;
            }
        }

        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), data[1] };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(data[0] == 0x37)  {
        if(fp_){
            fclose(fp_);
            fp_ = nullptr;
        }
        else{
            connection->sendNegativeAck(0x05);
        }
        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40) };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }
    else if(length > 2 && data[0] == 0x38)  {
        cout << "-> Send 0x38 message positive response" << endl;
        uint8_t mode = data[1];
        uint16_t filePathAndNameLength = ((uint16_t)data[2] << 8) | data[3];

        FileTransferAddFile result;
        if(!DeserializeFileTransferAddFile(filePathAndNameLength, data + 4, length - 4, result)){
            connection->sendNegativeAck(0x05);
            return;
        }

        if(mode == 1){
            fp_ = fopen(result.filePathAndName.c_str(), "wb");
            if(!fp_){
                //neg ack
                connection->sendNegativeAck(0x02);
                std::cout << "fopen failed:" << result.filePathAndName << std::endl;
                return;
            }

        unsigned char responseData[] = { (uint8_t)(data[0] + 0x40), 0x01, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00 };
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
        }
        else if(mode == 6){
            fp_ = fopen(result.filePathAndName.c_str(), "ab");
            if(!fp_){
                //neg ack
                connection->sendNegativeAck(0x03);
                std::cout << "fopen failed:" << result.filePathAndName << std::endl;
                return;
            }
            fseek(fp_, 0, SEEK_END);
            uint64_t fsize = ftell(fp_);
            std::cout << "ftell:" << result.filePathAndName << ",=:"<< fsize <<std::endl;
            u_int8_t lengthFormatIdentifier[] = {0x04};
            u_int8_t maxNumberOfBlockLength[] = {0x00, 0x10, 0x00, 0x00};
            u_int8_t dataFormatIdentifier[] = {0x00};
            std::vector<uint8_t> response_data;
            response_data.push_back(0x78);
            response_data.push_back(0x06);
            response_data.insert(response_data.end(), lengthFormatIdentifier, lengthFormatIdentifier+sizeof(lengthFormatIdentifier));
            response_data.insert(response_data.end(), maxNumberOfBlockLength, maxNumberOfBlockLength+sizeof(maxNumberOfBlockLength));
            response_data.insert(response_data.end(), dataFormatIdentifier, dataFormatIdentifier+sizeof(dataFormatIdentifier));
            std::cout << "fsize:" << "="<< std::setprecision(15) << fsize <<std::endl;
            fsize = htobe64(fsize);
            std::cout << "fsize:" << "="<< std::setprecision(15) << fsize << " after covert" <<std::endl;
            response_data.insert(response_data.end(), (uint8_t*)&fsize, (uint8_t*)&fsize+sizeof(uint64_t));

            connection->sendDiagnosticPayload(LOGICAL_ADDRESS, &response_data[0], response_data.size());
        }
        else{
            connection->sendNegativeAck(0x08);
        }
    }
    else {
        cout << "-> Send diagnostic message negative response" << endl;
        unsigned char responseData[] = { 0x7F, data[0], 0x11};
        connection->sendDiagnosticPayload(LOGICAL_ADDRESS, responseData, sizeof(responseData));
    }


}

/**
 * Will be called when the doip library receives a diagnostic message.
 * The library notifies the application about the message.
 * Checks if there is a ecu with the logical address
 * @param targetAddress     logical address to the ecu
 * @return                  If a positive or negative ACK should be send to the client
 */
bool DiagnosticMessageReceived(unsigned short targetAddress) {
    (void)targetAddress;
    unsigned char ackCode;

    cout << "Received Diagnostic message" << endl;
    //send positiv ack
    ackCode = 0x00;
    connection->sendDiagnosticAck(LOGICAL_ADDRESS, true, ackCode);

    return true;
}

/**
 * Closes the connection of the server by ending the listener threads
 */
void CloseConnection() {
    cout << "Connection closed" << endl;
    //serverActive = false;
}

/*
 * Check permantly if udp message was received
 */
void listenUdp() {

    while(serverActive) {
        server.receiveUdpMessage();
    }
}

/*
 * Check permantly if tcp message was received
 */
void listenTcp() {

    server.setupTcpSocket();

    while(true) {
        connection = server.waitForTcpConnection();
        connection->setCallback(ReceiveFromLibrary, DiagnosticMessageReceived, CloseConnection);
        connection->setGeneralInactivityTime(300);

         while(connection->isSocketActive()) {
             connection->receiveTcpMessage();
         }
    }
}

void ConfigureDoipServer() {

    server.setVIN("0123456789abcdefg");
    server.setLogicalGatewayAddress(LOGICAL_ADDRESS);
    server.setGID(0);
    server.setFAR(0);
    server.setEID(0);

    // doipserver->setA_DoIP_Announce_Num(tempNum);
    // doipserver->setA_DoIP_Announce_Interval(tempInterval);

}

int main() {
    ConfigureDoipServer();

    server.setupUdpSocket();

    serverActive = true;
    doipReceiver.push_back(thread(&listenUdp));
    doipReceiver.push_back(thread(&listenTcp));

    server.sendVehicleAnnouncement();

    doipReceiver.at(0).join();
    doipReceiver.at(1).join();
    return 0;
}
