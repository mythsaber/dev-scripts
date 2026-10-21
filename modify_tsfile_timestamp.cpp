// ============================================================================
// modify_tsfile_timestamp.cpp —— 按命令行参数修改 MPEG-TS 中 PTS/DTS 时间戳
//
// 主处理链路:
//   "读 TS 包 -> 解析包头/跳过自适应区 -> 定位 PES 起始包(PUSI=1 且负载以 0x000001 开头)
//    -> 解析 PES 中 PTS/DTS -> 按配置修改 -> 回写"
//
// 设计说明(为何不解析 PAT/PMT):
//   PTS/DTS 只存在于 PES 包的头部, 而每个 PES 包都以起始码 0x00 0x00 0x01 开头;
//   PAT/PMT/NIT/SDT 等 PSI 表的负载从 table_id 字节开始, 永远不以 0x000001 开头。
//   因此"PUSI=1 且负载以 0x000001 开头"足以识别所有携带 PTS/DTS 的媒体流,
//   天然排除 PSI 表, 无需解析 PAT/PMT——在缺少或损坏 PAT/PMT 的测试流上反而更鲁棒。
//   指定 target_pid 时严格匹配该 PID, 其余包原样写出;
//   未指定 target_pid 时处理所有携带 PTS/DTS 的媒体流。
//
// 时间戳修改参数(必填, 逗号分隔三部分):
//   <pts|dts|pdts>,<add|minus|mult>,<值|random(min,max)>
//     pts: 只修改 PTS;  dts: 只修改 DTS;  pdts: PTS 和 DTS 都修改
//     add / minus: 在原时间戳上 加 / 减, 值为整数(如 40, 或 random(-40,40))
//     mult: 在原时间戳上 乘, 值为浮点(如 0.2, 或 random(0.5,1.5))
//   时间戳为 33 位整数(0 ~ 0x1FFFFFFFF), 单位 90kHz 时钟节拍(1 秒 = 90000)。
// 
// Windows上msvc编译： 
//   打开x64 Native Tools Command Prompt for VS 2017
//   输入cl /EHsc /utf-8 modify_tsfile_timestamp.cpp编译，会生成.exe
//
// Linux上编译: g++ -std=c++11 -O2 -Wall -Wextra -o modify_tsfile_timestamp modify_tsfile_timestamp.cpp
// 运行: ./modify_tsfile_timestamp <input.ts> <output.ts> <pts,add,40> [pid|v|a]
//   pid|v|a(可选, 最后一个参数): 数字 = 严格匹配该 PID; v = 仅处理视频; a = 仅处理音频;
//   缺省(不设置) = 处理所有媒体
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <utility>
#include <vector>

typedef unsigned char u_char;

#define TS_PACKET_LENGTH 188
#define PTS_MASK         0x1FFFFFFFFULL   // 2^33 - 1, 33 位时间戳回绕上限

// 不携带 PTS/DTS 的非媒体 stream_id(被 classify_stream_id 的 fallthrough 排除)
#define STREAM_ID_PROGRAM_STREAM_MAP    0xbc
#define STREAM_ID_PRIVATE_STREAM_1      0xbd    // 常封装 AC-3/DTS 等音频, 按音频处理
#define STREAM_ID_PADDING_STREAM        0xbe
#define STREAM_ID_PRIVATE_STREAM_2      0xbf
#define STREAM_ID_ECM_STREAM            0xf0
#define STREAM_ID_EMM_STREAM            0xf1
#define STREAM_ID_DSMCC_STREAM          0xf2
#define STREAM_ID_H222_E_STREAM         0xf8
#define STREAM_ID_PROGRAM_STREAM_DIRECTORY 0xff

/*------------------------ 时间戳修改参数(必填, 第 3 个参数) ------------------------*/
// 修改目标
enum class TsTarget {
    PTS = 0,     // 只修改 PTS
    DTS,         // 只修改 DTS
    PDTS         // PTS 和 DTS 都修改
};

// 修改运算
enum class PtsOp {
    OP_ADD = 0,         // 在原时间戳上加一个值
    OP_MINUS,           // 在原时间戳上减一个值
    OP_MULT             // 在原时间戳上乘一个值
};

// 修改配置: 由 "<pts|dts|pdts>,<add|minus|mult>,<值|random(min,max)>" 解析而来。
// 值域: add/minus 为整数, mult 为浮点(double 可精确表示 2^53 内的整数)。
typedef struct {
    TsTarget target;       // 修改哪个字段
    PtsOp     op;           // 运算类型
    bool      is_random;    // true = 随机值, false = 固定值
    double    value;        // is_random 为 false 时的固定值
    double    rand_min;     // is_random 为 true 时的随机范围下界
    double    rand_max;     // is_random 为 true 时的随机范围上界
} TimestampModifyConfig;

// 解析时间戳修改参数 "<pts|dts|pdts>,<add|minus|mult>,<值|random(min,max)>"
// 成功返回 true 并填充 cfg; 失败返回 false
bool parse_ts_modify(const char* arg, TimestampModifyConfig& cfg){
    char target_str[8] = {0};
    char op_str[8] = {0};
    char value_str[64] = {0};
    // 前两段以逗号分隔, 第三段取到字符串末尾(内部可含逗号, 如 random(-40,40))
    if(sscanf(arg, "%7[^,],%7[^,],%63[^\n]", target_str, op_str, value_str) != 3){
        return false;
    }

    // 第一部分: pts / dts / pdts
    if(strcmp(target_str, "pts") == 0){
        cfg.target = TsTarget::PTS;
    }
    else if(strcmp(target_str, "dts") == 0){
        cfg.target = TsTarget::DTS;
    }
    else if(strcmp(target_str, "pdts") == 0){
        cfg.target = TsTarget::PDTS;
    }
    else{
        return false;
    }

    // 第二部分: add / minus / mult
    if(strcmp(op_str, "add") == 0){
        cfg.op = PtsOp::OP_ADD;
    }
    else if(strcmp(op_str, "minus") == 0){
        cfg.op = PtsOp::OP_MINUS;
    }
    else if(strcmp(op_str, "mult") == 0){
        cfg.op = PtsOp::OP_MULT;
    }
    else{
        return false;
    }

    // 第三部分: 具体值 或 random(min,max)
    cfg.is_random = false;
    cfg.value = 0;
    cfg.rand_min = 0;
    cfg.rand_max = 0;

    if(strncmp(value_str, "random(", 7) == 0){
        // 用 sscanf 解析 random(min,max); %lf 同时兼容整数与浮点,
        // %n 记录结束位置, 拒绝右括号后的残留
        int consumed = 0;
        if(sscanf(value_str, "random(%lf,%lf)%n",
                  &cfg.rand_min, &cfg.rand_max, &consumed) != 2 ||
           value_str[consumed] != '\0'){
            return false;
        }
        if(cfg.rand_min > cfg.rand_max){
            return false;
        }
        cfg.is_random = true;
    }
    else{
        // 具体数值
        char* p_end = nullptr;
        if(cfg.op == PtsOp::OP_MULT){
            cfg.value = strtod(value_str, &p_end);   // 乘法: 值可为浮点(如 0.2)
        }
        else{
            cfg.value = (double)strtoll(value_str, &p_end, 10);   // 加/减: 值为整数
        }
        if(*p_end != '\0'){
            return false;
        }
    }
    return true;
}

// 按配置修改时间戳。随机模式下, 本包 PTS 与 DTS 共用同一个随机值(保持相对差值)。
// add/minus 为整数偏移; mult 的乘数可为浮点, 但乘法结果立即四舍五入取整,
// 之后的运算与变量均为 int64_t, 符合时间戳的整数语义。
void apply_pts_modify(int64_t& new_pts, int64_t& new_dts,
                      int64_t old_pts, int64_t old_dts,
                      const TimestampModifyConfig& cfg, std::mt19937& gen){
    // 每包取一次随机值(随机模式下 PTS 与 DTS 共用)
    int64_t delta = 0;      // add/minus 的整数偏移
    double  mult  = 1.0;    // mult 的浮点乘数(可为小数)
    if(cfg.is_random){
        if(cfg.op == PtsOp::OP_MULT){
            std::uniform_real_distribution<double> dist(cfg.rand_min, cfg.rand_max);
            mult = dist(gen);
        }
        else{
            std::uniform_int_distribution<int64_t> dist((int64_t)cfg.rand_min, (int64_t)cfg.rand_max);
            delta = dist(gen);
        }
    }
    else{
        if(cfg.op == PtsOp::OP_MULT){
            mult = cfg.value;
        }
        else{
            delta = (int64_t)cfg.value;
        }
    }

    // 应用运算: mult 先乘浮点乘数再立即四舍五入回整数, 之后全部为 int64_t
    auto transform = [&](int64_t old_val) -> int64_t {
        int64_t result = old_val;
        if(cfg.op == PtsOp::OP_MULT){
            result = (int64_t)std::llround((double)old_val * mult);
        }
        else if(cfg.op == PtsOp::OP_ADD){
            result = old_val + delta;
        }
        else{   // OP_MINUS
            result = old_val - delta;
        }
        return result & (int64_t)PTS_MASK;
    };

    if((cfg.target == TsTarget::PTS || cfg.target == TsTarget::PDTS) && old_pts >= 0){
        new_pts = transform(old_pts);
    }
    if((cfg.target == TsTarget::DTS || cfg.target == TsTarget::PDTS) && old_dts >= 0){
        new_dts = transform(old_dts);
    }
}

/*------------------------------- 基础结构 -------------------------------*/
typedef struct PesPacketHeader{
    u_char start_code_prefix[3];        // 0x000001
    u_char stream_id[1];                // Audio (0xC0-0xDF), Video (0xE0-0xEF)
    u_char pes_packet_length[2];        // 0 means any length
} PesPacketHeader;

// PES stream_id 分类(不依赖 PAT/PMT)。
// find_pts_from_pes 用它过滤不携带 PTS/DTS 的非媒体流;
enum class MediaType {
    MEDIA_TYPE_NONE  = 0,   // 非媒体流, 不携带 PTS/DTS
    MEDIA_TYPE_VIDEO,       // 视频流 (0xE0-0xEF)
    MEDIA_TYPE_AUDIO        // 音频流 (0xC0-0xDF) / private_stream_1
};

MediaType classify_stream_id(u_char stream_id){
    if(stream_id >= 0xE0 && stream_id <= 0xEF){
        return MediaType::MEDIA_TYPE_VIDEO;
    }
    if(stream_id >= 0xC0 && stream_id <= 0xDF){
        return MediaType::MEDIA_TYPE_AUDIO;
    }
    if(stream_id == STREAM_ID_PRIVATE_STREAM_1){
        // 私有流一常封装 AC-3/DTS 等音频; 无 PMT 时无法精确区分, 按音频处理
        return MediaType::MEDIA_TYPE_AUDIO;
    }
    // 其余 stream_id(program_stream_map/padding/ECM/EMM/DSMCC 等)不携带 PTS/DTS
    return MediaType::MEDIA_TYPE_NONE;
}

/*------------------------------- 时间戳解析 -------------------------------*/
// 在 PES 负载中定位 PTS/DTS
// 返回 (pts_offset, dts_offset), 相对 buffer 起始位置; 不存在时为 0
std::pair<unsigned, unsigned> find_pts_from_pes(u_char* buffer, int buffer_length){
    if(buffer == nullptr || buffer_length < 9){
        return std::make_pair(0,0);
    }
    int cur_position = 0;
    // 解析pes头部, 一共6字节(结构体中 start_code_prefix 3 + stream_id 1 + length 2)
    PesPacketHeader pes_header;
    memcpy(&pes_header, buffer, 5);

    // 当前包没有pes头(不是 PES 包, 而是 PAT/PMT 等 PSI 表或私有数据)
    if(pes_header.start_code_prefix[0] != 0x00 ||
       pes_header.start_code_prefix[1] != 0x00 ||
       pes_header.start_code_prefix[2] != 0x01){
        return std::make_pair(0,0);
    }
    // 非媒体流不解析pts
    if(classify_stream_id(pes_header.stream_id[0]) == MediaType::MEDIA_TYPE_NONE){
        return std::make_pair(0,0);
    }
    cur_position += 6;

    // 直接解析 OptionalPesHeader(避免内存分配)
    if(buffer_length - cur_position < 3){
        return std::make_pair(0,0);
    }

    u_char byte0 = buffer[cur_position];                    // 标志字节 1
    u_char byte1 = buffer[cur_position + 1];                // 标志字节 2(PTS_DTS_flags 等)
    u_char header_data_length = buffer[cur_position + 2];   // PES_header_data_length
    u_char pts_dts_indicator = (byte1 >> 6) & 0x03;
    u_char marker_bits = (byte0 >> 6) & 0x03;

    // 如果开头不是2, 就不是pes adaptation header
    if(marker_bits != 2){
        return std::make_pair(0,0);
    }
    // pts_dts指示表示并不存在pts_dts
    if(pts_dts_indicator == 0b00){
        return std::make_pair(0,0);
    }

    // 有optional header与pts/dts, 先移动位置
    cur_position += 3;

    // 双重校验, 防止畸形流越界读或把负载误当时间戳:
    //   1) PES_header_data_length 必须足以容纳所声明的时间戳字段(PTS 是可选头第一段)
    //   2) 实际剩余空间必须足以容纳时间戳字段
    if(pts_dts_indicator == 0b11){
        if(header_data_length < 10 || buffer_length - cur_position < 10){
            return std::make_pair(0,0);   // 长度声明或剩余空间不足 PTS(5)+DTS(5)
        }
        return std::make_pair(cur_position, cur_position+5);
    }
    // 只有PTS存在
    else if(pts_dts_indicator == 0b10){
        if(header_data_length < 5 || buffer_length - cur_position < 5){
            return std::make_pair(0,0);   // 长度声明或剩余空间不足 PTS(5)
        }
        return std::make_pair(cur_position, 0);
    }
    else{
        return std::make_pair(0,0);
    }
}

// 从 5 字节 PTS/DTS 字段读出 33 位时间戳(PTS和DTS编码格式相同)
uint64_t combine_pts(char buffer[5]) {
    uint64_t pts_num = 0;
    pts_num |= ((uint64_t)buffer[0] & 0b00001110) << 29;
    pts_num |= ((uint64_t)buffer[1] & 0b11111111) << 22;
    pts_num |= ((uint64_t)buffer[2] & 0b11111110) << 14;
    pts_num |= ((uint64_t)buffer[3] & 0b11111111) << 7;
    pts_num |= ((uint64_t)buffer[4] & 0b11111110) >> 1;
    return pts_num;
}

// 把 33 位时间戳写入 5 字节 PTS/DTS 字段
// PTS 编码格式：5字节, 33位PTS值, 带有标记位
void rewrite_pts(char* payload, uint64_t pts){
    payload[0] = (char)(0x21 | ((pts >> 29) & 0x0E));  // '0010' + PTS[32-30] + marker
    payload[1] = (char)((pts >> 22) & 0xFF);           // PTS[29-22]
    payload[2] = (char)(0x01 | ((pts >> 14) & 0xFE));  // marker + PTS[21-15]
    payload[3] = (char)((pts >> 7) & 0xFF);            // PTS[14-7]
    payload[4] = (char)(0x01 | ((pts << 1) & 0xFE));   // marker + PTS[6-0]
}

// 处理一个 PES 包的时间戳: 解析 old_pts/old_dts -> 按配置修改 -> 覆写 new_pts/new_dts
// buffer 指向整个 TS 包, cur_position 为负载起始位置
// 返回本包实际修改的字段个数(0/1/2)
int process_pes_packet(u_char* buffer, int cur_position, int buffer_length,
                       const TimestampModifyConfig& cfg, std::mt19937& gen){
    // 定位 PTS/DTS 相对负载的偏移
    std::pair<unsigned, unsigned> pts_pair = find_pts_from_pes(&buffer[cur_position], buffer_length);
    if(pts_pair.first == 0 && pts_pair.second == 0){
        return 0;   // 本包没有时间戳
    }

    // 原始时间戳, 不存在时为 -1
    int64_t old_pts = -1, old_dts = -1;
    if(pts_pair.first != 0){
        old_pts = (int64_t)combine_pts((char*)&buffer[cur_position + pts_pair.first]);
    }
    if(pts_pair.second != 0){
        old_dts = (int64_t)combine_pts((char*)&buffer[cur_position + pts_pair.second]);
    }

    // 初始化为原值; 按配置修改需要改的字段
    int64_t new_pts = old_pts;
    int64_t new_dts = old_dts;
    apply_pts_modify(new_pts, new_dts, old_pts, old_dts, cfg, gen);

    int modified = 0;
    // new = -1 表示不修改; 原字段不存在时无法写入
    if(pts_pair.first != 0 && new_pts >= 0 && new_pts != old_pts){
        rewrite_pts((char*)&buffer[cur_position + pts_pair.first], ((uint64_t)new_pts) & PTS_MASK);
        modified++;
    }
    if(pts_pair.second != 0 && new_dts >= 0 && new_dts != old_dts){
        rewrite_pts((char*)&buffer[cur_position + pts_pair.second], ((uint64_t)new_dts) & PTS_MASK);
        modified++;
    }
    return modified;
}

/*------------------------------- 同步搜索 -------------------------------*/
// 从文件当前位置开始逐字节查找 0x47 同步字节。
// triple 为 true 时做三重确认: 要求该字节后 TS_PACKET_LENGTH 与 2*TS_PACKET_LENGTH
// 处也必须是 0x47, 才认为真正找到了同步位置(用于初始同步, 防止把文件开头多余
// 字节中偶然出现的 0x47 误判为同步)。
// 扫描过程中每个未同步的字节(非 0x47, 或三重确认失败的 0x47)都收集进 pending,
// 由调用方在找到同步后原样写入输出文件, 保证失步字节不丢失。
// 返回找到的 0x47 的绝对文件偏移; 未找到(到文件末尾)返回 -1。
long long find_next_sync_byte(std::ifstream& file_in, bool triple, std::vector<u_char>& pending){
    long long pos = (long long)file_in.tellg();
    char c = 0;
    while(true){
        file_in.clear();    // 清除上次读取可能留下的 EOF/失败标志
        file_in.seekg((std::streamoff)pos, std::ios::beg);
        file_in.read(&c, 1);
        if(file_in.gcount() != 1){
            return -1;      // 到文件末尾仍未找到
        }
        if((u_char)c != 0x47){
            pending.push_back((u_char)c);   // 未同步字节, 原样保留
            pos++;
            continue;
        }
        if(!triple){
            return pos;
        }
        // 三重确认: pos+188 与 pos+376 处也必须是 0x47
        char c1 = 0, c2 = 0;
        file_in.clear();
        file_in.seekg((std::streamoff)(pos + TS_PACKET_LENGTH), std::ios::beg);
        file_in.read(&c1, 1);
        bool ok1 = (file_in.gcount() == 1 && (u_char)c1 == 0x47);
        file_in.clear();
        file_in.seekg((std::streamoff)(pos + 2 * TS_PACKET_LENGTH), std::ios::beg);
        file_in.read(&c2, 1);
        bool ok2 = (file_in.gcount() == 1 && (u_char)c2 == 0x47);
        if(ok1 && ok2){
            return pos;
        }
        // 不满足三重确认: 该 0x47 只是偶然出现, 作为未同步字节原样保留
        pending.push_back((u_char)c);
        pos++;
    }
}

// 从输入流读取一个有效 TS 包(自动处理初始同步与失步重同步)。
//   - 首次: 通过三重确认找到真正的同步位置;
//   - 已同步: 直接读 TS_PACKET_LENGTH 字节;
//   - 若读到的不以 0x47 开头(失步): 回退到本包起始位置重新找 0x47 重同步。
// 同步期间所有未同步的字节(文件开头多余字节、失步段、末尾残留)都原样写入
// file_out, 输出字节级保真。dirty_byte_cnt 累计写出的未同步字节数。
// 返回 true 表示 buffer 中装好了一个以 0x47 开头的有效包; false 表示文件结束。
bool read_next_ts_packet(std::ifstream& file_in, std::ofstream& file_out,
                      u_char buffer[TS_PACKET_LENGTH], bool& synced,
                      long long& dirty_byte_cnt){
    std::vector<u_char> pending;    // 本次同步过程中收集的未同步字节
    while(true){
        if(!synced){
            // 初始/失步重同步: 三重确认后定位到真正的同步字节
            long long sync_pos = find_next_sync_byte(file_in, true, pending);
            if(sync_pos < 0){
                // 到文件末尾仍未找到同步: 把剩余未同步字节原样写出后结束
                if(!pending.empty()){
                    file_out.write((const char*)pending.data(), (std::streamsize)pending.size());
                    dirty_byte_cnt += (long long)pending.size();
                }
                return false;
            }
            // 找到同步: 先把扫描期间收集的未同步字节原样写出
            if(!pending.empty()){
                file_out.write((const char*)pending.data(), (std::streamsize)pending.size());
                dirty_byte_cnt += (long long)pending.size();
                pending.clear();
            }
            file_in.clear();
            file_in.seekg((std::streamoff)sync_pos, std::ios::beg);
            synced = true;
        }

        file_in.read((char*)buffer, TS_PACKET_LENGTH);
        if(file_in.gcount() != TS_PACKET_LENGTH){
            // 到达文件末尾, 剩余不足一个完整包: 残留字节也原样写出, 保证输出不丢字节
            if(file_in.gcount() > 0){
                file_out.write((const char*)buffer, (std::streamsize)file_in.gcount());
                dirty_byte_cnt += (long long)file_in.gcount();
            }
            return false;       // 读取不完整, 到达文件末尾
        }
        if(buffer[0] == 0x47){
            return true;
        }

        // 失步: 本包全部视为未同步字节。回退到本包起始位置, 由
        // find_next_sync_byte 逐字节重同步, 期间的每个字节都会被原样写出。
        file_in.clear();
        file_in.seekg((std::streamoff)(-TS_PACKET_LENGTH), std::ios::cur);
        synced = false;
    }
}

/*------------------------------- 主流程 -------------------------------*/
// 媒体过滤模式(CLI 最后一个参数)
enum class MediaMode {
    ALL = 0,     // 缺省: 处理所有携带 PTS/DTS 的媒体流
    VIDEO,       // v: 仅处理视频
    AUDIO        // a: 仅处理音频
};

// 逐包处理
int process_file(const char* input_path, const char* output_path,
                 int target_pid, MediaMode media_mode,
                 const TimestampModifyConfig& modify_cfg){
    // 开启输入文件(二进制只读)
    std::ifstream file_in(input_path, std::ios::binary);
    if(!file_in.is_open()){
        std::cerr << "Failed to open the input file: " << input_path << std::endl;
        return -1;
    }

    // 开启输出文件
    std::ofstream file_out(output_path, std::ios::binary);
    if(!file_out.is_open()){
        std::cerr << "Failed to open the output file: " << output_path << std::endl;
        return -1;
    }

    u_char buffer[TS_PACKET_LENGTH];

    // 统计信息
    long long get_packet_cnt = 0;       // 读取的 TS 包总数
    long long write_packet_cnt = 0;     // 写入的 TS 包总数
    long long dirty_byte_cnt = 0;       // 原样写出的未同步字节数
    long long pes_packet_cnt = 0;       // 含时间戳的 PES 起始包数
    long long modified_packet_cnt = 0;  // 发生时间戳修改的包数

    bool synced = false;    // 同步状态: false 表示尚未同步(初始需三重确认, 失步后单字节重同步)

    // 随机引擎: 随机模式下每包从 [rand_min, rand_max] 取一个值
    std::mt19937 gen(std::random_device{}());

    while(read_next_ts_packet(file_in, file_out, buffer, synced, dirty_byte_cnt)){
        get_packet_cnt++;

        // 解析ts头
        u_char* buf_ptr = buffer;
        // 同步字节已由上文保证为 0x47
        u_char transport_error_indicator = (buf_ptr[1] >> 7) & 0x01;
        u_char payload_unit_start_indicator = (buf_ptr[1] >> 6) & 0x01;
        int pid = ((buf_ptr[1] & 0x1F) << 8) | buf_ptr[2];
        u_char adaption_field_control = (buf_ptr[3] >> 4) & 0x03;

        if(transport_error_indicator == 1){
            std::cout << "Transport error indicator set, packet may be corrupted" << std::endl;
        }

        // PID 直接匹配模式: 严格匹配 target_pid, 其余包原样写出
        if(target_pid > 0 && pid != target_pid){
            file_out.write((const char*)buffer, TS_PACKET_LENGTH);
            write_packet_cnt++;
            continue;
        }

        int cur_position = 4;

        // 跳过自适应区
        if(adaption_field_control == 0x2 || adaption_field_control == 0x3){
            int adaptation_field_length = (int)buffer[cur_position];
            // 自适应区长度不应该超过包剩余空间
            if(cur_position + 1 + adaptation_field_length > TS_PACKET_LENGTH){
                file_out.write((const char*)buffer, TS_PACKET_LENGTH);
                write_packet_cnt++;
                continue;
            }
            cur_position += adaptation_field_length;
            cur_position ++;
        }
        else if(adaption_field_control == 0b01){
            cur_position += 0;
        }
        // 无负载(adaption_field_control == 0x00)
        else{
            file_out.write((const char*)buffer, TS_PACKET_LENGTH);
            write_packet_cnt++;
            continue;
        }

        // 检查负载位置是否有效
        if(cur_position >= TS_PACKET_LENGTH){
            file_out.write((const char*)buffer, TS_PACKET_LENGTH);
            write_packet_cnt++;
            continue;
        }

        // PTS/DTS 只出现在 PES 起始包(payload_unit_start_indicator == 1)。
        // 再用 PES 起始码 0x000001 判定负载是否为 PES 包——PAT/PMT 等 PSI 表
        // 的负载从 table_id 字节开始, 天然被排除, 因此无需解析 PAT/PMT。
        // v/a 模式在下方按 PES stream_id 分类过滤媒体类型。
        if(payload_unit_start_indicator == 1 && cur_position + 3 < TS_PACKET_LENGTH){
            if(buffer[cur_position] == 0x00 &&
               buffer[cur_position + 1] == 0x00 &&
               buffer[cur_position + 2] == 0x01){
                // v/a 模式: 按 PES stream_id 分类, 只处理对应媒体类型
                bool pass = true;
                if(target_pid <= 0 && media_mode != MediaMode::ALL){
                    MediaType mt = classify_stream_id(buffer[cur_position + 3]);
                    pass = (media_mode == MediaMode::VIDEO) ? (mt == MediaType::MEDIA_TYPE_VIDEO)
                                                                       : (mt == MediaType::MEDIA_TYPE_AUDIO);
                }
                if(pass){
                    pes_packet_cnt++;
                    int modified = process_pes_packet(buffer, cur_position, TS_PACKET_LENGTH - cur_position,
                                                      modify_cfg, gen);
                    if(modified > 0){
                        modified_packet_cnt++;
                    }
                }
            }
        }

        file_out.write((const char*)buffer, TS_PACKET_LENGTH);
        write_packet_cnt++;
    }

    // 统计信息
    std::cout << "get ts packet cnt:        " << get_packet_cnt << std::endl;
    std::cout << "write ts packet cnt:      " << write_packet_cnt << std::endl;
    std::cout << "unsynced byte written:    " << dirty_byte_cnt << std::endl;
    std::cout << "pes packet(has pts/dts):  " << pes_packet_cnt << std::endl;
    std::cout << "modified packet cnt:      " << modified_packet_cnt << std::endl;

    return 0;
}

// 解析目标过滤参数: 数字 PID / v(视频) / a(音频)
// 成功返回 true; 失败打印错误信息并返回 false
bool parse_target_filter(const char* arg, int& target_pid, MediaMode& media_mode){
    if(arg[0] == 'v' && arg[1] == '\0'){
        media_mode = MediaMode::VIDEO;
    }
    else if(arg[0] == 'a' && arg[1] == '\0'){
        media_mode = MediaMode::AUDIO;
    }
    else{
        target_pid = std::atoi(arg);
        if(target_pid <= 0){
            std::cerr << "Invalid argument: " << arg << " (应为数字 PID / v / a)" << std::endl;
            return false;
        }
    }
    return true;
}

int main(int argc, char* argv[]){
    if(argc < 4 || argc > 5){
        std::cerr << "Usage: " << argv[0] << " <input.ts> <output.ts> <pts,add,40> [pid|v|a]" << std::endl;
        std::cerr << "  时间戳修改(必填): <pts|dts|pdts>,<add|minus|mult>,<值|random(min,max)>" << std::endl;
        std::cerr << "    例: pts,add,40  /  pdts,minus,random(-40,40)  /  dts,mult,0.2" << std::endl;
        std::cerr << "  pid|v|a(可选, 最后一个参数): 数字 = 仅处理该 PID; v = 仅处理视频; a = 仅处理音频; 缺省 = 处理所有媒体" << std::endl;
        return -1;
    }

    int target_pid = -1;
    MediaMode media_mode = MediaMode::ALL;

    // argv[3]: 时间戳修改参数(必填)
    TimestampModifyConfig modify_cfg;
    if(!parse_ts_modify(argv[3], modify_cfg)){
        std::cerr << "Invalid modify arg: " << argv[3] << std::endl;
        return -1;
    }

    // argv[4](可选, 最后一个参数): 目标过滤 pid|v|a
    if(argc == 5){
        if(!parse_target_filter(argv[4], target_pid, media_mode)){
            return -1;
        }
    }

    return process_file(argv[1], argv[2], target_pid, media_mode, modify_cfg);
}
