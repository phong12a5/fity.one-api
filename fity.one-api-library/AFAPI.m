//
// Created by phong.dang on 9/5/2019.
//
#include <AFAPI.h>
#include <UIKit/UIKit.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <CkoJsonObject.h>
#include <CkoCrypt2.h>
#include <CkoHttp.h>
#include <CkoHttpResponse.h>
#include <CkoHttpRequest.h>
#include <CkoJsonArray.h>
#include <CkoRest.h>
#include <CkoBinData.h>
#include <CkoGlobal.h>
#include <CkoDateTime.h>
#include <CkoDtObj.h>
#include <CkoStream.h>
#include <CkoZip.h>
#include <CkoSocket.h>
#include <CkoImap.h>
#include <CkoEmailBundle.h>
#include <CkoEmail.h>
#include <CkoStringBuilder.h>
#include <CkoMessageSet.h>
#include <CkoRsa.h>
#include <CkoPrivateKey.h>
#include <CkoCert.h>
#include "auto-genereted-cert.h"

#define KEY_PAIR std::pair<std::string, std::string>
#define KEY_PREFIX "Congaubeo@123"

#define DEBUG_LEVEL 0
#define INFO_LEVEL 1
#define ERROR_LEVEL 2

static BOOL unlockChilkat()
{
    CkoGlobal* glob = [[CkoGlobal alloc] init];
    if (![glob UnlockBundle:@"AUTFRM.CB4082023_Pz2Ry7az86p4"]) {
        PLog(@"Error: %@", glob.LastErrorText);
        return NO;
    }

    if ([glob.UnlockStatus intValue] == 2) {
        PLog(@"Unlocked using purchased unlock code.");
    } else {
        PLog(@"Unlocked in trial mode.");
    }
    return YES;
}

static NSString* getCurrentTime()
{
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = gmtime(&t);

    char buffer[20];
    snprintf(buffer, 20, "%4d:%02d:%02d:%02d:%02d:%02d", (tmp->tm_year + 1900), (tmp->tm_mon + 1), tmp->tm_mday, tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
    return [NSString stringWithUTF8String:buffer];
}

static NSString* hash(NSString* input, int nBlock, int blockSize)
{
    NSMutableString* result = [NSMutableString string];
    if (input.length >= blockSize && 16 % blockSize == 0)
    {
        for (int i = 0; i < nBlock; i++)
        {
            if (i + blockSize - 1 < input.length)
            {
                [result appendString:[input substringWithRange:NSMakeRange(i, blockSize)]];
            }
            else
            {
                [result appendString:[input substringWithRange:NSMakeRange(input.length - blockSize, blockSize)]];
            }
        }
    }
    return result;
}

static BOOL getKeyIv(NSString* uid, NSString** key, NSString** iv)
{
    *key = hash(uid,4,8);
    *iv = hash(uid,4,4);
    return YES;
}

static NSString* Encrypt(NSString* input, NSString* key, NSString* iv)
{
	PLog(@"key: %@ -- iv: %@ -- input: %@", key, iv, input);
    CkoCrypt2* crypt = [[CkoCrypt2 alloc] init];
    crypt.CryptAlgorithm = @"aes";
    crypt.CipherMode = @"cbc";
    crypt.KeyLength = @256;
    crypt.PaddingScheme = 0;
    crypt.EncodingMode = @"base64";
    [crypt SetEncodedIV:iv encoding:@"ascii"];
    [crypt SetEncodedKey: key encoding:@"ascii"];
    return [crypt EncryptStringENC:input];
}

static NSString* Decrypt(NSString* input, NSString* key, NSString* iv)
{
	PLog(@"key: %@ -- iv: %@ -- input: %@", key, iv, input);
    CkoCrypt2* crypt = [[CkoCrypt2 alloc] init];
    crypt.CryptAlgorithm = @"aes";
    crypt.CipherMode = @"cbc";
    crypt.KeyLength = @256;
    crypt.PaddingScheme = 0;
    crypt.EncodingMode = @"base64";
    [crypt SetEncodedIV:iv encoding:@"ascii"];
    [crypt SetEncodedKey: key encoding:@"ascii"];
    return [crypt DecryptStringENC:input];
}

static NSString* md5(NSString* input) {
    CkoCrypt2* crypt = [[CkoCrypt2 alloc] init];
    // The desired output is a hexidecimal string:
    crypt.EncodingMode = @"hex";

    // Set the hash algorithm:
    crypt.HashAlgorithm = @"md5";
    return [crypt HashStringENC:input];
}

static NSString* encryptTimestamp(NSString* timestamp, NSString* token)
{
    NSString* keyFromToken = hash(token, 4, 8);
    NSString* ivFromToken = hash(token, 4, 4);
    return Encrypt(timestamp, keyFromToken, ivFromToken);
}

static NSString* decryptTimestamp(NSString* timestamp, NSString* token)
{
    NSString* keyFromToken = hash(token, 4, 8);
    NSString* ivFromToken = hash(token, 4, 4);
    return Decrypt(timestamp, keyFromToken, ivFromToken);
}

static NSString* getKeyFromTimestamp(NSString* timeStamp)
{
    NSString* key = [NSString stringWithFormat:@"%@%@%@",@KEY_PREFIX, timeStamp, timeStamp];
    return [key substringWithRange:NSMakeRange(0, 32)];
}

static NSDictionary* getDynamicKey()
{
    NSString* currTime = getCurrentTime();
    NSString* outputKey = getKeyFromTimestamp(currTime);
    return @{@"key":outputKey, @"time_stamp":currTime};
}

static BOOL loadJson(CkoJsonObject** json, NSString * jsonStr) {
    return [*json Load:jsonStr] && [(*json).Size intValue] > 0;
}
/*
static void getListContentOfCloudFolder(const char *folderPath, CkoJsonObject *output, std::string &token)
{
    PLog(@"folderPath: %s", folderPath);
    CkRest rest;
    rest.put_ConnectTimeoutMs(30000);
    bool bTls = true;
    int port = 443;
    bool bAutoReconnect = true;
    if (!rest.Connect("api.dropboxapi.com", port, bTls, bAutoReconnect))
    {
        PLog(@"ConnectFailReason: %d", rest.get_ConnectFailReason());
        PLog(@"Error: %s", rest.lastErrorText());
        return;
    }

    //  See the Online Tool for Generating JSON Creation Code
    CkoJsonObject json;
    json.UpdateString("path", folderPath);
    json.UpdateBool("recursive", false);
    json.UpdateBool("include_media_info", false);
    json.UpdateBool("include_deleted", false);
    json.UpdateBool("include_has_explicit_shared_members", false);
    json.UpdateBool("include_mounted_folders", true);

    //  Add request headers.
    std::string tokenStr = "Bearer " + token;
    rest.AddHeader("Authorization", tokenStr.data());
    rest.AddHeader("Content-Type", "application/json");

    CkStringBuilder sbRequestBody;
    json.EmitSb(sbRequestBody);
    CkStringBuilder sbResponseBody;
    if (!rest.FullRequestSb("POST", "/2/files/list_folder", sbRequestBody, sbResponseBody))
    {
        PLog(@"rest.FullRequestSb: %s", rest.lastErrorText());
        return;
    }

    int respStatusCode = rest.get_ResponseStatusCode();
    if (respStatusCode >= 400)
    {
        PLog(@"Response Status Code = %d", respStatusCode);
        PLog(@"Response Header: %s", rest.responseHeader());
        PLog(@"Response Body: %s", sbResponseBody.getAsString());
        return;
    }

    CkoJsonObject jsonResponse;
    jsonResponse.LoadSb(sbResponseBody);

    //  See the Online Tool for Generating JSON Parse Code
    int i;
    int count_i;

    jsonResponse.stringOf("cursor");
    jsonResponse.BoolOf("has_more");
    i = 0;
    count_i = jsonResponse.SizeOfArray("entries");
    while (i < count_i)
    {
        jsonResponse.put_I(i);
        const char *Tag = jsonResponse.stringOf("entries[i].\".tag\"");
        const char *name = jsonResponse.stringOf("entries[i].name");
        if (output->IndexOf(name) == -1)
        {
            output->UpdateString(name, Tag);
        }
        i = i + 1;
    }
}

static void getJsonCommon(CkoJsonObject &object, std::vector<std::string> &keyList, std::vector<std::string> &valueList, int fieldNumber)
{
    srand(time(nullptr));
    if (keyList.size() == valueList.size() &&
        fieldNumber <= static_cast<int>(keyList.size()))
    {

        for (int i = 0; i < fieldNumber; i++)
        {
            int randIndex = i + rand() % (fieldNumber - i);
            std::string key = keyList[randIndex];
            keyList[randIndex] = keyList[i];
            keyList[i] = key;

            randIndex = i + rand() % (fieldNumber - i);
            std::string value = valueList[randIndex];
            valueList[randIndex] = valueList[i];
            valueList[i] = value;

            KEY_PAIR keyPair = getDynamicKey();
            static std::string tmpiv = "phongdeptrai_phongvandeptrai_01071994";
            object.UpdateString(key.data(), encrypt(value.data(), keyPair.first.data(),
                                                    tmpiv.substr(2, 16).data())
                                                .data());
        }
    }
}
*/

static BOOL getCert(CkoCert** cert, E_SUPPORTED_PLATFORM platform) {
	PLog(@"platform: %d", (int)platform);
    NSString* en_cert, *en_privatekey, *keyPass;

    switch (platform) {
    case PLATFORM_F_IOS:
        en_cert = [NSString stringWithUTF8String:en_cert5];
        en_privatekey = [NSString stringWithUTF8String:en_privatekey5];
        keyPass = @"client5";
        break;
    case PLATFORM_F_IOS_WEBVIEW:
        en_cert = [NSString stringWithUTF8String:en_cert6];
        en_privatekey = [NSString stringWithUTF8String:en_privatekey6];
        keyPass = @"client6";
        break;
    default:
        return NO;
    }
	NSString* deCert = Decrypt(en_cert, md5(@"phong.dang"), [md5(@"pdt") substringWithRange:NSMakeRange(0, 16)]);
    if (![*cert LoadPem:deCert]) {
        PLog(@"Load cert error: %@",(*cert).LastErrorText);
        return NO;
    }

    CkoPrivateKey* privKey = [[CkoPrivateKey alloc] init];
	NSString* dePrivateKey = Decrypt(en_privatekey ,md5(@"dang.phong") ,[md5(@"pdt") substringWithRange:NSMakeRange(0, 16)]);

    if (![privKey LoadEncryptedPem:dePrivateKey  password:keyPass]) {
        PLog(@"load key error: %@",privKey.LastErrorText);
        return NO;
    };

   PLog(@"privKey: %@",[privKey GetPkcs8Pem]);
    // Associate the private key with the cert.
    if (![*cert SetPrivateKey:privKey]) {
        PLog(@"SetPrivateKey error: %@",(*cert).LastErrorText);
        return NO;
    }

    return YES;
}

static void deviceInfo2CkoJson(CkoJsonObject** json, E_SUPPORTED_PLATFORM platform,  DEVICE_INFO device_info) {
    [*json UpdateString:@"device_id" value:device_info.device_id];
    [*json UpdateString:@"app_version_name" value:device_info.app_version_name];

    switch (platform) {
    case PLATFORM_F_IOS:
        [*json UpdateString:@"system" value:@"f_ios"];
        break;
    case PLATFORM_F_IOS_WEBVIEW:
        [*json UpdateString:@"system" value:@"f_ios_webview"];
        break;
    default:
        [*json UpdateString:@"system" value:@"unknown"];
        break;
    }
}

@implementation AFAPI {
    BOOL m_initState;
    BOOL m_unlockState;
    NSString* m_token;
    E_SUPPORTED_PLATFORM m_system_type;
    CkoJsonObject* m_deviceInfo;
    NSString* m_dropBoxToken;
    NSString* m_domain;
}

-(instancetype) init;
{
    self = [super init];
    if(self) {
#if defined (F_IOS)
    m_system_type = PLATFORM_F_IOS;
#elif defined (IOS_WEBVIEW)
    m_system_type = PLATFORM_F_IOS_WEBVIEW;
#else
    m_system_type = PLATFORM_UNKNOWN;
#endif
        m_initState = NO;
        m_token = nil;
        m_unlockState = unlockChilkat();
        m_dropBoxToken = nil;
    }
    PLog(@"**************************** Created WebAPI instance --- Phong Dep Trai! ****************************");
    return self;
}

+ (instancetype)instance {
	static dispatch_once_t once = 0;
	__strong static id sharedInstance = nil;
	dispatch_once(&once, ^{
		sharedInstance = [self new];
	});
	return sharedInstance;
}

+(NSString*) version {
    return @"0.0.1";
}

/* Private */

-(BOOL) downloadFile: (NSString*)url savedPath:(NSString* )savedPath
{
    CkoHttp* http = [[CkoHttp alloc] init];
    http.ConnectTimeout = @30;
    http.ReadTimeout = @30;

    if (![http Download:url saveToPath:savedPath])
    {
        PLog(@"Error: %@", http.LastErrorText);
        return NO;
    }
    return YES;
}

-(NSString*) getKey
{
    return @"Congaubeo@123456Congaubeo@123456";
}

-(NSString*) getIv
{
    return @"Congaubeo@123560";
}

-(NSString*) getDomain
{
    switch (m_system_type) {
    case PLATFORM_F_IOS:
        return @"https://api5.fity.one/cgi-bin/fity-one.cgi?system=f_ios";
    case PLATFORM_F_IOS_WEBVIEW:
        return @"https://api6.fity.one/cgi-bin/fity-one.cgi?system=f_ios_webview";
    default:
        return nil;
    }
}

-(NSString*) getUrlByAPI: (NSString*) api
{
    return [NSString stringWithFormat:@"%@&api=%@&token=%@", [self getDomain], api,m_token];
}

-(BOOL) encryptCloneInfo: (NSString**) cloneInfo
{
    BOOL retVal = NO;
    CkoJsonObject* cloneInfoObj = [[CkoJsonObject alloc] init];
    if (loadJson(&cloneInfoObj,*cloneInfo)) {
        if ([cloneInfoObj HasMember:@"uid"]) {
            NSString* uid = [cloneInfoObj StringOf:@"uid"];
            NSString* key = [[NSString alloc] init];
            NSString* iv = [[NSString alloc] init];
            getKeyIv(uid, &key, &iv);
            PLog(@"uid: %@ -- key: %@ -- iv: %@", uid, key, iv);

            if (key.length == 32 && iv.length == 16) {
                CkoJsonObject* mzz = [[CkoJsonObject alloc] init];
                if ([cloneInfoObj HasMember:@"password"]) {
                    NSString* password = [cloneInfoObj StringOf:@"password"];
                    NSString* enPassword = Encrypt(password, key, iv);
                    [cloneInfoObj UpdateString:@"password" value: enPassword];
                    [mzz UpdateBool:@"p" value:true];
                }

                if ([cloneInfoObj HasMember:@"secretkey"]) {
                    NSString* scretkey = [cloneInfoObj StringOf:@"secretkey"];
                    NSString* enSecretkey = Encrypt(scretkey, key, iv);
                    [cloneInfoObj UpdateString:@"secretkey" value: enSecretkey];
                    [mzz UpdateBool:@"s" value: YES];
                }

                [cloneInfoObj Delete:@"mzz"];
                [cloneInfoObj AddObjectCopyAt: @-1 name:@"mzz" jsonObj:mzz];
                *cloneInfo = [cloneInfoObj Emit];
                retVal = YES;
            } else  {
                PLog(@"invalid key: %@ or iv: %@", key, iv);
            }
        } else {
            PLog(@"No uid!");
        }
    } else  {
        PLog(@"Parse cloneInfo failed");
    }
    return retVal;
}

-(BOOL) decryptCloneInfo: (NSString**) cloneInfo
{
    BOOL retVal = NO;
    CkoJsonObject* cloneInfoObj = [[CkoJsonObject alloc] init];
    if (loadJson(&cloneInfoObj,*cloneInfo)) {
        if ([cloneInfoObj HasMember:@"uid"]) {
            NSString* uid = [cloneInfoObj StringOf:@"uid"];
            NSString* key = [[NSString alloc] init];
            NSString* iv = [[NSString alloc] init];
            getKeyIv(uid, &key, &iv);
            PLog(@"uid: %@ -- key: %@ -- iv: %@", uid, key, iv);

            if (key.length == 32 && iv.length == 16) {
                CkoJsonObject* mzz = [cloneInfoObj ObjectOf:@"mzz"];

                if ([cloneInfoObj HasMember:@"password"] && mzz != nil && [mzz BoolOf:@"p"])
                {
                    NSString* enPassword = [cloneInfoObj StringOf:@"password"];
                    NSString* password = Decrypt(enPassword, key, iv);
                    [cloneInfoObj UpdateString:@"password" value: password];
                }

                if ([cloneInfoObj HasMember:@"secretkey"] && mzz != nil && [mzz BoolOf:@"s"])
                {
                    NSString* enScretkey = [cloneInfoObj StringOf:@"secretkey"];
                    NSString* secretkey = Decrypt(enScretkey, key, iv);
                    [cloneInfoObj UpdateString:@"secretkey" value: secretkey];
                }

                *cloneInfo = [cloneInfoObj Emit];
                retVal = true;
            } else  {
                PLog(@"invalid key: %@ or iv: %@", key, iv);
            }
        } else {
            PLog(@"No uid!");
        }
    } else {
        PLog(@"Parse cloneInfo failed");
    }
    return retVal;
}

-(BOOL) initWebAPIs: (NSString *) token device_info:(DEVICE_INFO) deviceInfo
{
    PLog(@"initWebAPIs");
    if(deviceInfo.device_id == nil || deviceInfo.device_id.length == 0) {
        PLog(@"Invalid device_id!");
    } else if (token == nil || token.length == 0) {
        PLog(@"Invalid token");
    }
    else
    {
        m_initState = YES;
        m_token = token;
        CkoJsonObject* deviceInfoJson = [[CkoJsonObject alloc] init];
        deviceInfo2CkoJson(&deviceInfoJson, m_system_type, deviceInfo);
        m_deviceInfo = deviceInfoJson;
        PLog(@"m_token: %@ -- m_deviceInfo: %@", m_token, [m_deviceInfo Emit]);
    }

    PLog(@"initWebAPIs: %@", (m_initState ? @"successful" : @"failure"));
    return m_initState;
}

-(BOOL) sendRequest:(CkoJsonObject*)bodyData 
                response:(CkoJsonObject**)response 
                api:(NSString *)api 
                extraDeviceInfo:(NSDictionary *) extraDeviceInfo
{
    PLog(@"url: %@ \n data: %@",[self getUrlByAPI: api], [bodyData Emit]);
    bool success = NO;
    if (m_initState)
    {
		[bodyData AddObjectCopyAt:@-1 name:@"device_info" jsonObj: m_deviceInfo];
		[bodyData UpdateString:@"token" value: m_token];

        NSDictionary* keyPair = getDynamicKey();
        NSString* enData = Encrypt([bodyData Emit], [keyPair objectForKey: @"key"], [self getIv]);
        NSString* enClientTimestamp = encryptTimestamp([keyPair objectForKey:@"time_stamp"], m_token);

        CkoJsonObject* jsonReqBody = [[CkoJsonObject alloc] init];
        [jsonReqBody UpdateString:@"data" value: enData];
        [jsonReqBody UpdateString:@"client_timestamp" value:enClientTimestamp];

        CkoHttp* http = [[CkoHttp alloc] init];
        http.ConnectTimeout = @30;
        http.ReadTimeout = @30;
        [http SetRequestHeader:@"Content-Type" value:@"application/json"];
        [http SetRequestHeader:@"mobile-secret-key" value:md5(m_token)];

        CkoCert* cert = [[CkoCert alloc] init];
        if(!getCert(&cert, m_system_type)) {
            PLog(@"GetCert failed!: %@", http.LastErrorText);
            [*response UpdateString:@"error" value:@"GetCert failed!"];
        } else if(![http SetSslClientCert: cert]) {
            PLog(@"SetSslClientCert error: %@", http.LastErrorText);
            [*response UpdateString:@"error" value:@"SetSslClientCert failed!"];
        } else {
            PLog(@"Apply certificate successfully!");
            CkoHttpResponse *resp = [http PostJson: [self getUrlByAPI:api] jsonText:[jsonReqBody Emit]];

            if (!http.LastMethodSuccess) {
                [*response UpdateString:@"error" value: http.LastErrorText];
            } else {
                if (resp.BodyStr != nil) {
                    PLog(@"BodyStr: %@", resp.BodyStr);
                    CkoJsonObject* jsonResponse = [[CkoJsonObject alloc] init];
                    if (loadJson(&jsonResponse, resp.BodyStr)) {
                        jsonResponse.EmitCompact = NO;
                        if ([jsonResponse HasMember:@"data"]) {
                            if ([jsonResponse HasMember:@"server_timestamp"]) {
                                NSString* serverTimeStamp = [jsonResponse StringOf:@"server_timestamp"];
                                serverTimeStamp = decryptTimestamp(serverTimeStamp, m_token);

                                NSString* key = getKeyFromTimestamp(serverTimeStamp);
                                NSString* data = Decrypt([jsonResponse StringOf:@"data"], key, [self getIv]);

                                PLog(@"decoded data: %@", data);
                                CkoJsonObject* responseData = [[CkoJsonObject alloc] init];

                                if (loadJson(&responseData, data)) {
                                    if ([responseData HasMember:@"data"]) {
                                        CkoJsonObject* server_data = [[CkoJsonObject alloc] init];
                                        if (loadJson(&server_data, [responseData StringOf:@"data"])) {
                                            if ([server_data HasMember:@"data"]) {
                                                CkoBinData* ckstr = [[CkoBinData alloc] init];
                                                [ckstr AppendEncoded:[server_data StringOf:@"data"] encoding: @"base64"];
                                                [server_data UpdateString:@"data" value: [ckstr GetString:@"utf-8"]];
                                            }
                                            [*response AddObjectCopyAt: @-1 name: @"data"  jsonObj: server_data];
                                        }
                                    }

                                    if ([responseData HasMember:@"cgi_message"]) {
                                        [*response UpdateString:@"cgi_message" value: [responseData StringOf:@"cgi_message"]];
                                    }

                                    if ([responseData HasMember:@"response_code"]) {
                                        [*response UpdateInt:@"response_code" value: [responseData IntOf:@"response_code"]];
                                    }

                                    if ([responseData HasMember:@"success"]) {
                                        [*response UpdateBool:@"success" value: [responseData BoolOf:@"success"]];
                                    }
                                    success = YES;
                                }
                            } else {
                                [*response UpdateString:@"error_message"  value: @"could not obtain server_timestamp"];
                            }
                        } else {
                            [*response UpdateString:@"error" value: @"\"data\" field don't existed!"];
                        }
                    } else {
                        [*response UpdateString:@"error" value: @"Could not load response -> json"];
                        [*response UpdateString:@"response" value: resp.BodyStr];
                    }
                } else {
                    [*response UpdateString:@"error" value: @"response: NULL"];
                }
            }
        }
    } else {
        [*response UpdateString:@"error" value:@"Init WebAPI failed"];
    }
    PLog(@"response: %@", [*response Emit]);
    return success;
}

// Autofarmer APIs
-(NSDictionary*) upsertDevice:(NSDictionary*)  extraDeviceInfo
{
    PLog(@"");
    NSMutableDictionary* retVal = [NSMutableDictionary dictionary];
    [retVal setObject:@NO forKey:@"success"];

    CkoJsonObject* bodyData = [[CkoJsonObject alloc] init];
    CkoJsonObject* response = [[CkoJsonObject alloc] init];

    [bodyData UpdateString:@"action" value:@"Upsert"];

    if ([self sendRequest:bodyData response:&response api:@"config" extraDeviceInfo:extraDeviceInfo]) {
        CkoJsonObject *server_data = [response ObjectOf:@"data"];
        if (server_data != nil) {
            if ([server_data HasMember:@"code"]) {
                [retVal setObject:[server_data IntOf:@"code"] forKey:@"code"];
                [retVal setObject: @([[server_data IntOf:@"code"] intValue] == 200) forKey:@"success" ];
            }

            if ([server_data HasMember:@"message"]) {
                [retVal setObject: [server_data StringOf:@"message"] forKey:@"message" ];
            }
        }
    }
    PLog(@"retVal: %@", retVal);
    return retVal;
}

/*
std::string WebAPI::updateDeviceInfo(const char * extraDeviceInfo) {
    PLog(@"");
    CkoJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "UpdateDeviceInfo");

    if (sendRequest( __FUNCTION__ , bodyData, response, "config", extraDeviceInfo)) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

-(NSString*) getConfig
{
    PLog(@"");
    CkoJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetConfig");

    if (sendRequest( __FUNCTION__ ,bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
            }

            if (server_data->HasMember("version")) {
                retVal.UpdateString("version", server_data->stringOf("version"));
            }

            if (server_data->HasMember("new_token")) {
                retVal.UpdateString("new_token", server_data->stringOf("new_token"));
            }

            if (server_data->HasMember("data")) {
                const char *data = server_data->stringOf("data");
                CkoJsonObject configJson;
                if (loadJson(configJson, data)) {
                    retVal.AddObjectCopyAt(-1, "data", configJson);
                    retVal.UpdateBool("success", true);

                    if (configJson.HasMember("dropboxaccesstoken")) {
                        m_dropBoxToken = std::string(configJson.stringOf("dropboxaccesstoken"));
                    } else {
                        retVal.UpdateString("warning_message",
                                            "Dropboxaccesstoken field is not existed!");
                    }
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getClone()
{
    PLog(@"");
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetClone");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data)  {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkoJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data()))
                {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getCloneInfo(const char *clone_info)
{
    PLog(@"clone_info: %s", clone_info);
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    std::string cloneInfoStr = std::string(clone_info);
    encryptCloneInfo(cloneInfoStr);
    PLog(@"cloneInfoStr: %s", cloneInfoStr.data());

    CkString str;
    str.put_Utf8(true);
    str.setString(cloneInfoStr.data());
    str.base64Encode("utf-8");

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetCloneInfo");
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest(__FUNCTION__ , bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkoJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data())) {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getStoredClones()
{
    PLog(@"");
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetStoredClones");

    if (sendRequest(__FUNCTION__ , bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                CkJsonArray storedClones;
                storedClones.put_Utf8(true);
                if (storedClones.Load(data.data())) {
                    retVal.AddArrayCopyAt(-1, "data", storedClones);
                } else {
                    PLog(@"Load data failed");
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::updateClone(const char * action, const char *cloneJsonPath)
{
    PLog(@"action: %s -- cloneJsonPath: %s",action, cloneJsonPath);
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    std::string cloneInfoStr = std::string(cloneJsonPath);
    encryptCloneInfo(cloneInfoStr);
    PLog(@"cloneInfoStr: %s", cloneInfoStr.data());

    CkString str;
    str.put_Utf8(true);
    str.setString(cloneInfoStr.data());
    str.base64Encode("utf-8");

    CkoJsonObject bodyData, response, cloneInfo;
    bodyData.UpdateString("action", action);
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest( __FUNCTION__ , bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {

            if (server_data->HasMember("code")) {
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkoJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data())) {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::doAction(const char *clone_id)
{
    PLog(@"clone_id: %s", clone_id);
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("clone_id", clone_id);

    if (sendRequest( __FUNCTION__ , bodyData, response, "get-do-actions")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("data")) {
                CkJsonArray actionsArr;
                actionsArr.put_Utf8(true);
                if(actionsArr.Load(server_data->stringOf("data")))
                retVal.AddArrayCopyAt(-1, "data", actionsArr);
            }

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::doResult(const char *clone_id, const char *dataJsonPath)
{
    PLog(@"clone_id: %s -- dataJsonPath: %s", clone_id, dataJsonPath);
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response, actionObj;
    bodyData.UpdateString("clone_id", clone_id);
    if (loadJson(actionObj,dataJsonPath))
        bodyData.AddObjectCopyAt(-1, "data", actionObj);

    if (sendRequest( __FUNCTION__, bodyData, response, "do-result")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200 || server_data->IntOf("code") == 400 || server_data->IntOf("code") == 401);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"result: %s",retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getJasmineDefinitions()
{
    PLog(@"");
    CkoJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetJasmine");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("data")) {
                CkJsonArray definitionArr;
                definitionArr.put_Utf8(true);
                if(definitionArr.Load(server_data->stringOf("data"))) {
                    retVal.UpdateBool("success", true);
                    retVal.AddArrayCopyAt(-1, "data", definitionArr);
                }
            }
        }
    }
    PLog(@"result: %s",retVal.emit());
    return retVal.emit();
}

std::string WebAPI::submitActiveClones(const char *activeClones)
{
    PLog(@"activeClones: %s", activeClones);
    CkoJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    CkJsonArray activeCloneArr;
    if (activeCloneArr.Load(activeClones)) bodyData.AddArrayCopyAt(-1, "clone_ids", activeCloneArr);
    bodyData.UpdateString("action", "SubmitActiveClones");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200 || server_data->IntOf("code") == 400);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getHotmail()
{
    PLog(@"");
    CkoJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkoJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetHotMail");

    if (sendRequest( __FUNCTION__, bodyData, response, "config"))
    {
        CkoJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code") && server_data->IntOf("code") == 200)
            {
                retVal.UpdateBool("success", true);
            }

            if (server_data->HasMember("data"))
            {
                CkoJsonObject emailObj;
                emailObj.put_Utf8(true);
                if (loadJson(emailObj,server_data->stringOf("data")))
                {
                    retVal.AddObjectCopyAt(-1, "data", emailObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    PLog(@"retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getCodeFromImap(const char * imapServer, int port, const char * mailBox, const char * fromName, const char* toEmail, const char * login_email, const char * login_password) const {
    PLog(@"email: %s -- passwd: %s", login_email, login_password);
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    //outlook: 993
    imap.put_Port(port);
    imap.put_Ssl(true);
    //outlook: "outlook.office365.com"
    bool success = imap.Connect(imapServer);
    if (!success)
    {
        PLog(@"imap.Connect: %s", imap.lastErrorText());
        return "";
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        PLog(@"imap.sendRawCommand: %s", imap.lastErrorText());
        return "";
    }

    // Login
    success = imap.Login(login_email, login_password);
    if (!success) {
        PLog(@"imap.Login: %s", imap.lastErrorText());
        return "";
    }

    PLog(@"Login Success!");

    std::string code;

    //outlook: "Inbox"
    success = imap.SelectMailbox(mailBox);
    if (!success) {
        PLog(@"imap.SelectMailbox: %s", imap.lastErrorText());
        return "";
    } else {
        PLog(@"SelectMailbox success!");
    }

    // We can choose to fetch UIDs or sequence numbers.
    bool fetchUids = true;
    // Get the message IDs of all the emails in the mailbox
    CkMessageSet *messageSet = imap.Search("ALL", fetchUids);
    if (!imap.get_LastMethodSuccess()) {
        PLog(@"imap.Search: %s", imap.lastErrorText());
        return "";
    } else {
        PLog(@"Search ALL mail box success!");
    }

    // Fetch the emails into a bundle object:
    CkEmailBundle *bundle = imap.FetchBundle(*messageSet);
    if (!imap.get_LastMethodSuccess()) {
        delete messageSet;
        messageSet = nullptr;
        PLog(@"imap.FetchBundle: %s", imap.lastErrorText());
        return "";
    } else {
        PLog(@"FetchBundle success!");
    }

    // Loop over the bundle and display the FROM and SUBJECT of each.
    int i = 0;
    int numEmails = bundle->get_MessageCount();
    while (i < numEmails) {
        CkEmail *ckEmail = bundle->GetEmail(i);
        PLog(@"email from -> %s", ckEmail->ck_from());
        PLog(@"email to -> %s", ckEmail->getToAddr(0));
        PLog(@"email subject -> %s", ckEmail->subject());

        if (std::string(ckEmail->ck_from()).find(fromName) != std::string::npos ||
            std::string(ckEmail->getToAddr(0)).find(toEmail) != std::string::npos) {
            PLog(@"body: %s", ckEmail->body());
            std::cmatch veriCodeMatchValue;
            if (regex_search(ckEmail->body(), veriCodeMatchValue, std::regex("\\d{5,7}"))) {
                code = veriCodeMatchValue[0];
                //bool SetFlag(int msgId, bool bUid, const char *flagName, int value);
                // delete email
                imap.SetFlag(ckEmail->GetImapUid(), true, "Deleted", 1);
            }
        }
        delete ckEmail;
        i = i + 1;
    }

    // Expunge and close the mailbox.
    success = imap.ExpungeAndClose();

    delete messageSet;
    delete bundle;

    // Disconnect from the IMAP server.
    success = imap.Disconnect();
    PLog(@"code: %s", code.data());
    return code;
}

// Dropbox APIs

bool WebAPI::downloadFileFromDropbox(const char *pathFile, const char *savePath)
{
    PLog(@"pathFile: %s -- savePath: %s", pathFile, savePath);
    CkRest rest;
    rest.put_IdleTimeoutMs(120000);

    //  Connect to Dropbox
    if (!rest.Connect("content.dropboxapi.com", 443, true, true))
    {
        PLog(@"Connect error: %s", rest.lastErrorText());
        return false;
    }

    std::string token;
    if (!getDropboxToken(token))
    {
        PLog(@"Get dropbox token failed");
        return false;
    }
    //  Add request headers.
    std::string tokenStr = "Bearer " + token;
    rest.AddHeader("Authorization", tokenStr.data());

    CkoJsonObject json;
    json.AppendString("path", pathFile);
    rest.AddHeader("Dropbox-API-Arg", json.emit());

    CkStream fileStream;
    fileStream.put_SinkFile(savePath);

    int expectedStatus = 200;
    rest.SetResponseBodyStream(expectedStatus, true, fileStream);

    rest.fullRequestNoBody("POST", "/2/files/download");
    if (!rest.get_LastMethodSuccess())
    {
        PLog(@"responseStr error: %s", rest.lastErrorText());
        return false;
    }
    //  When successful, Dropbox responds with a 200 response code.
    if (rest.get_ResponseStatusCode() != 200)
    {
        //  Examine the request/response to see what happened.
        PLog(@"response status code = %d", rest.get_ResponseStatusCode());
        PLog(@"response status text = %s", rest.responseStatusText());
        PLog(@"response header: %s", rest.responseHeader());
        PLog(@"response body (if any): %s", rest.readRespBodyString());
        PLog(@"LastRequestStartLine: %s", rest.lastRequestStartLine());
        PLog(@"LastRequestHeader: %s", rest.lastRequestHeader());
        PLog(@"lastErrorText: %s", rest.lastErrorText());
        return false;
    }
    PLog(@"Download %s successful", pathFile);
    return true;
}

std::string WebAPI::getFacebookCodeFromCGBDomainMail(const char * email) const {
    PLog(@"email: %s", email);
    return getCodeFromImap("imap.yandex.com", 993, "Spam", "Facebook", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");
}

std::string WebAPI::getTiktokCodeFromCGBDomainMail(const char * email) const {
    PLog(@"email: %s", email);
    return getCodeFromImap("imap.yandex.com", 993, "Inbox", "TikTok", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");
}

std::string WebAPI::getFacebookCodeFromHotmail(const char * email, const char * password) const {
    PLog(@"email: %s -- passwd: %s", email, password);
    return getCodeFromImap("outlook.office365.com", 993, "Inbox", "Facebook", email, email, password);
}

std::string WebAPI::getTiktokCodeFromHotmail(const char * email, const char * password) const {
    return getCodeFromImap("outlook.office365.com", 993, "Inbox", "TikTok", email, email, password);
}

bool WebAPI::checkLoginHotmail(std::string &email, std::string &password) const
{
    PLog(@"email: %s -- passwd: %s", email.data(), password.data());
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    imap.put_Port(993);
    imap.put_Ssl(true);
    bool success = imap.Connect("outlook.office365.com");
    if (!success)
    {
        PLog(@"imap.Connect: %s", imap.lastErrorText());
        return false;
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        PLog(@"imap.sendRawCommand: %s", imap.lastErrorText());
        return false;
    }

    // Login
    success = imap.Login(email.c_str(), password.c_str());
    if (!success)
    {
        PLog(@"imap.Login: %s", imap.lastErrorText());
        return false;
    }

    PLog(@"Login Success!");
    return true;
}

std::string WebAPI::tOTP(const char * secretkey) {
    std::string result;
    if(secretkey) {
        // Do the following to calculate the 6-digit decimal Google authenticator token for a base32 secret,
        // given the current system date/time.
        CkCrypt2 crypt;
        result = crypt.totp(secretkey,"base32","0","",30,6,-1,"sha1");
    }
    return result;
}
*/
@end