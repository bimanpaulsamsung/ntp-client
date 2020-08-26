/* Copyright (c) 2019 ARM, Arm Limited and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ntp-client/NTPClient.h"
#include "mbed.h"
#include "wifi.h"

#define WIFI_WRITE_TIMEOUT 10000
#define WIFI_READ_TIMEOUT  10000

NTPClient::NTPClient()
    : nist_server_address(NTP_DEFULT_NIST_SERVER_ADDRESS), nist_server_port(NTP_DEFULT_NIST_SERVER_PORT) {
}

void NTPClient::set_server(const char* server, int port) {
    nist_server_address = server;
    nist_server_port = port;
}

time_t NTPClient::get_timestamp() {
    const time_t TIME1970 = (time_t)2208988800UL;
    int ntp_send_values[12] = {0};
    uint32_t ntp_recv_values[12] = {0};
    uint8_t ntp_timesec[4] = {0};
    uint8_t remoteip[4] = {0,};
    uint8_t socket = 0;
    int wifi_code;
    uint16_t ret;
    uint16_t n;

	if (WIFI_GetHostAddress((char *)nist_server_address, remoteip) != WIFI_STATUS_OK) {
		printf("ERROR: DNS Resolution failed\n");
	}

        memset(ntp_send_values, 0x00, sizeof(ntp_send_values));
        ntp_send_values[0] = '\x1b';

        memset(ntp_recv_values, 0x00, sizeof(ntp_recv_values));


        if (WIFI_OpenClientConnection(socket, WIFI_UDP_PROTOCOL, "ntp",
        		remoteip, nist_server_port, 1111) != WIFI_STATUS_OK) {
        	printf("ERROR: UDP Socket for NTP Failed\n");
        	return 0;
        }

        printf("SENDING...\n");
        wifi_code = WIFI_SendData(socket, (uint8_t *)ntp_send_values, sizeof(ntp_send_values), &ret, WIFI_WRITE_TIMEOUT);
        printf("RECEIVING...\n");
        wifi_code = WIFI_ReceiveData(socket, (uint8_t *)ntp_recv_values, sizeof(ntp_recv_values), &n, WIFI_READ_TIMEOUT);
        printf("RECEIVED...\n");
        if (WIFI_CloseClientConnection(socket) != WIFI_STATUS_OK) {
			printf("ERROR: UDP Socket Close for NTP Failed\n");
		}

        if (n > 10) {
        	memcpy(ntp_timesec, ntp_recv_values + 10, 4);

        	printf("TIME STAMP NTP: %02x %02x %02x %02x\n", ntp_timesec[0], ntp_timesec[1], ntp_timesec[2], ntp_timesec[3]);
        	uint32_t epochtime = ntohl(ntp_recv_values[10]);
        	printf("SECONDS NTP: %u, 0x%x\n", epochtime, epochtime);
        	printf("SECONDS EPOCH: %u, 0x%x\n", epochtime- TIME1970, epochtime- TIME1970);
            return ntohl(ntp_recv_values[10]) - TIME1970;

        } else {
            if (n < 0) {
                // Network error
                return 0;

            } else {
                // No or partial data returned
                return -1;
            }
        }
}

uint32_t NTPClient::ntohl(uint32_t x) {
    uint32_t ret = (x & 0xff) << 24;
    ret |= (x & 0xff00) << 8;
    ret |= (x & 0xff0000UL) >> 8;
    ret |= (x & 0xff000000UL) >> 24;
    return ret;
}
