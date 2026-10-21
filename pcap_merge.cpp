#include <iostream>
#include <vector>
#include <string>
#include <utility>
#include "pcap.h"

void Merge(const std::vector<std::string>& input_files, const std::string& output_file)
{
    if (input_files.empty())
    {
        return;
    }

    std::string inLog;
    for (const auto& i : input_files)
    {
        inLog += "; ";
        inLog += i;
    }
    printf("merge %s, out %s\n", inLog.c_str(), output_file.c_str());


    // 获取链路类型
    int datalink_type;
    for(const auto& input_file : input_files)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap_in = pcap_open_offline(input_file.c_str(), errbuf);
        if (!pcap_in)
        {
            printf("pcap_open_offline(%s) failed: %s\n", input_file.c_str(), errbuf);
            continue;
        }
        datalink_type = pcap_datalink(pcap_in);
        pcap_close(pcap_in); // 关闭输入文件
        printf("datalink_type=%d\n",datalink_type);
        break;
    }

    pcap_t* pcap_out = pcap_open_dead(datalink_type, 65535); // 创建一个虚拟的pcap句柄
    if (!pcap_out)
    {
        printf("pcap_open_dead failed\n");
        return;
    }

    // 写入pcap文件头
    pcap_dumper_t* dumper = pcap_dump_open(pcap_out, output_file.c_str());
    if (!dumper)
    {
        printf("pcap_dump_open failed\n");
        pcap_close(pcap_out);
        return;
    }

    for (const auto& input_file : input_files)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap_in = pcap_open_offline(input_file.c_str(), errbuf);
        if (!pcap_in)
        {
            printf("pcap_open_offline(%s) failed: %s\n", input_file.c_str(), errbuf);
            continue;
        }

        struct pcap_pkthdr* header;
        const u_char* packet;

        // 读取每个输入文件的包并写入输出文件
        while(pcap_next_ex(pcap_in, &header, &packet)>=0)
        {
            if(header->caplen < header->len)
            {
                printf("warn: caplen=%u, len=%u\n",header->caplen, header->len);
            }
            pcap_dump((u_char*)dumper, header, packet);
        }

        pcap_close(pcap_in);
    }

    pcap_dump_close(dumper);
    pcap_close(pcap_out);
}

int main() 
{
    std::vector<std::string> input_files = { /*"20241111_180515_503871.pcap", 
						"20241111_180525_526495.pcap",*/
						 "20241111_180535_544980.pcap" };
    std::string output_file = "merged.pcap";

    Merge(input_files, output_file);

    std::cout << "合并完成，输出文件: " << output_file << std::endl;

    return 0;
}
