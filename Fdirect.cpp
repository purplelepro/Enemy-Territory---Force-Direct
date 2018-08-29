#include <iostream>
#include <iterator>
#include <algorithm>
#include <string>
#include <string.h>
#include <ctime>
#include <memory>
#include <cstdint>

#include <arpa/inet.h>
#include <sys/socket.h>

#define INET_ERROR -1

inline bool HasQ3Prefix(char *data)
{
	if((int)data[0] == -1 && (int)data[1] == -1 && (int)data[2] == -1 && (int)data[3] == -1)
		return true;
	return false;
}

inline std::string EscapeQ3PrefixToString(char *data)
{
	std::string str = std::string(data);
	return str.substr(4, str.length());
}

inline std::string GetAddrToString(sockaddr_in *addr)
{
	return std::string(inet_ntoa(addr->sin_addr));
}

void Q3Send(int sock, sockaddr *addr, socklen_t slen, std::string str)
{
	char data[1024];
	data[0] = -1;
	data[1] = -1;
	data[2] = -1;
	data[3] = -1;
	sprintf(data + 4, "%s", str.c_str());
	if (sendto(sock, data, str.length() + 4, 0, (struct sockaddr*)addr, slen) == INET_ERROR)
	{
		std::cout << "[-] Something went wrong with sendto" << std::endl;
		exit(1);
	}
}

template <typename... Ts>
std::string StringSprintf(const std::string &fmt, Ts... vs)
{
    char b;
    size_t required = std::snprintf(&b, 0, fmt.c_str(), vs...) + 1;
    char bytes[required];
    std::snprintf(bytes, required, fmt.c_str(), vs...);
    return std::string(bytes);
}

std::string GetRandomString(size_t len)
{
	auto randchar = []() -> char {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };
    std::string str(len, 0);
    std::generate_n( str.begin(), len, randchar );
    return str;
}

#define LOCAL_PORT 				27963
#define MASTERSERVER_PORT 		27950
#define MASTERSERVER_ADDRESS 	"192.246.40.60"
#define TARGET_SERVER_ADDRESS   "193.33.177.117:26020"

int main(int argc, char **argv)
{
	struct sockaddr_in si_me, si_other, si_master;
	int sock, slen = sizeof(si_other) , recv_len = 0;
	
	std::string heartbeat = "heartbeat EnemyTerritory-1";
	std::string status    = "statusResponse\n\\omnibot_playing\\0\\omnibot_enable\\1\\p\\1\\voteFlags\\1\\g_balancedteams\\1\\g_bluelimbotime\\10000\\g_redlimbotime\\10000\\gamename\\silent\\mod_version\\0.9.0\\mod_url\\0\\mod_binary\\linux-release\\sv_uptime\\44d12h22m\\sv_cpu\\Intel(R) Xeon(R) CPU\\g_heavyWeaponRestriction\\100\\g_gametype\\2\\g_antilag\\1\\g_voteFlags\\0\\g_alliedmaxlives\\0\\g_axismaxlives\\0\\g_minGameClients\\0\\g_needpass\\0\\g_maxlives\\0\\g_friendlyFire\\0\\sv_allowAnonymouse\\0\\sv_floodProtect\\1\\sv_maxPing\\0\\sv_minPing\\0\\sv_maxRate\\25000\\sv_minguidage\\0\\sv_punkbuster\\0\\sv_hostname\\^6NO BOTS ^3NOOBS ^1ELITE\\mapname\\goldrush\\protocol\\84\\timelimit\\30\\version\\ET 3.00 - TB 0.7.4 linux-i386\\sv_maxclients\\64\n34894 48 \"^fFishboi\"\n43827 50 \"^0mirAge\"\n13453 48 \"^iANMLZD ^7hurricAne\"\n9993 148 \"^1ANMLZD ^7NightmAre\"\n8592 50 \"^1D^0Ri*^1^1^1L^0AW^1Y^0E^1R\"\n187043 148 \"^1D^0Ri*^1a^0j\"\n78372 51 \"^1D^0Ri*^1D^0aRk^1P^0iMp*\"\n23823 50 \"^1D^0Ri*^1R^0el^1!^0c*\"\n187043 148 \"^1D^0Ri*^1V^0J^1*\"\n";
	std::string info      = "infoResponse\n\\protocol\\84\\hostname\\^6NO BOTS ^3NOOBS ^1ELITE\\serverload\\0\\mapname\\goldrush\\clients\\66\\sv_maxclients\\80\\gametype\\4\\pure\\1\\game\\silent\\sv_allowAnonymous\\0\\friendlyFire\\0\\maxlives\\0\\needpass\\0\\punkbuster\\0\\gamename\\et\\g_antilag\\1\\weaprestrict\\100\\balancedteams\\1\\challenge\\";
	std::string challenge = "challengeResponse 1234567890";
	std::string redirect  = StringSprintf("print\nET://%s", TARGET_SERVER_ADDRESS);
	
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INET_ERROR)
	{
		std::cout << "[-] Cannot open a socket" << std::endl;
		exit(1);
	}
	
	memset((char *)&si_me, 0, sizeof(si_me));
	
	si_me.sin_family 		= AF_INET;
    si_me.sin_port 			= htons(LOCAL_PORT);
    si_me.sin_addr.s_addr 	= htonl(INADDR_ANY);
	
	if(bind(sock, (struct sockaddr*)&si_me, sizeof(si_me)) == INET_ERROR)
    {
        std::cout << "[-] Cannot bind socket" << std::endl;
		exit(1);
    }
	
	memset((char *)&si_master, 0, sizeof(si_master));
    si_master.sin_family = AF_INET;
    si_master.sin_port 	 = htons(MASTERSERVER_PORT);
	if (inet_aton(MASTERSERVER_ADDRESS, &si_master.sin_addr) == 0) 
    {
        std::cout << "[-] inet_aton error when resolving address" << std::endl;
        exit(1);
    }
	
	std::cout << "[+] Sending heartbeat for the first time" << std::endl;
	Q3Send(sock, (struct sockaddr*) &si_master, sizeof(si_master), heartbeat);
	
	time_t time_start = time(NULL);
	for( ; ; )
	{
		char recv_buff[2048] = { 0 };
		int time_delta = (time(NULL) - time_start) / 60;
		
		if(time_delta >= 5)
		{
			std::cout << "[+] Sending heartbeat to master" << std::endl;
			Q3Send(sock, (struct sockaddr*) &si_master, sizeof(si_master), heartbeat);
			time_start = time(NULL);
		}
		
		if ((recv_len = recvfrom(sock, recv_buff, sizeof(recv_buff), 0, (struct sockaddr *) &si_other, (socklen_t *)&slen)) == INET_ERROR)
        {
            std::cout << "[-] Something went wrong with recvfrom" << std::endl;
			exit(1);
        }
		
		if(recv_len > 0 && HasQ3Prefix(recv_buff))
		{
			std::string recv_string = EscapeQ3PrefixToString(recv_buff);
			
			std::cout << "[debug] " << "packet len: " << recv_len << " received q3prefix(" << HasQ3Prefix(recv_buff) << "): " << recv_buff << std::endl;
			
			if(GetAddrToString(&si_other).find(MASTERSERVER_ADDRESS) != std::string::npos)
			{
				std::cout << "[+] Masterserver scanning me now" << std::endl;
			}
			if(recv_string.find("getstatus") != std::string::npos)
			{
				Q3Send(sock, (struct sockaddr*) &si_other, sizeof(si_other), status);
			}
			if(recv_string.find("getinfo") != std::string::npos)
			{
				std::cout << "[+] " << GetAddrToString(&si_other) << " saw the redirect server" << std::endl;
				Q3Send(sock, (struct sockaddr*) &si_other, sizeof(si_other), info);
			}
			if(recv_string.find("getchallenge") != std::string::npos)
			{		
				std::cout << "[+] " << GetAddrToString(&si_other) << " getting challenge" << std::endl;
				Q3Send(sock, (struct sockaddr*) &si_other, sizeof(si_other), challenge);
			}
			if(recv_string.find("connect") != std::string::npos)
			{
				std::cout << "[+] " << GetAddrToString(&si_other) << " connected to the server" << std::endl;
				Q3Send(sock, (struct sockaddr*) &si_other, sizeof(si_other), redirect);
			}
		}
	}
	return 0;
}









