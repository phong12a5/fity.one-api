//
// Created by phong.dang on 9/5/2019.
//

#ifndef WEBAPI_H
#define WEBAPI_H

#include <vector>
#include <string>
#include <list>
#include <map>

class CkJsonObject;

class WebAPI {
private:
    WebAPI();

public:
    enum E_SUPPORTED_PLATFORM: int {
        PLATFORM_UNKNOWN = 0,
        PLATFORM_F_CARE,
        PLATFORM_F_SYSTEM,
        PLATFORM_F_ANDROID,
        PLATFORM_F_ANDROID_WEBVIEW,
        PLATFORM_F_IOS,
        PLATFORM_F_IOS_WEBVIEW
    };


    static WebAPI* getInstance();
    static std::string version();

    bool initWebAPIs(E_SUPPORTED_PLATFORM platform, const char * token, const char * deviceInfo);

    // Config APIs
    std::string upsertDevice(const char * extraDeviceInfo);
    std::string updateDeviceInfo(const char * extraDeviceInfo);
    std::string getConfig();
    std::string getClone(const char * appName);
    std::string getCloneInfo(const char *appName, const char * clone_info);
    std::string getStoredClones(const char *appName);
    std::string updateClone(const char * action, const char *appName, const char * cloneJsonPath);
    std::string getJasmineDefinitions();
    std::string submitActiveClones(const char * activeClones);

    // Get actions APIs
    std::string doAction(const char * clone_id);

    // Submit Result APIs
    bool doResult(const char * clone_id, const char * dataJsonPath);

    // Dropbox APIs
    bool downloadFileFromDropbox(const char* pathFile, const char* savePath);
    std::string getFolderContent(const char * folderPath);

    // Hotmail APIs
    std::string getHotmail();
    bool        checkLoginHotmail(std::string& email, std::string& password) const;
    std::string getFacebookCodeFromCGBDomainMail(const char * email) const;
    std::string getTiktokCodeFromCGBDomainMail(const char * email) const;
    std::string getFacebookCodeFromHotmail(const char * email, const char * password) const;
    std::string getTiktokCodeFromHotmail(const char * email, const char * password) const;

    //util
    static std::string tOTP(const char * secretkey);
    static bool downloadFile(std::string& url, const std::string& savedPath);


private:
    bool initState() const;
    void setInitState(bool state);
    bool getDropboxToken(std::string &dropboxToken);
    std::string getDomain();
    std::string getUrlByAPI(std::string api);
    static const char * getKey();
    static const char * getIv();
    static bool unlockChilkat();
    static bool makeDir(const char * folderName);
    bool encryptCloneInfo(std::string& cloneInfo);
    bool decryptCloneInfo(std::string& cloneInfo);
    bool sendRequest(const char * caller, CkJsonObject& data, CkJsonObject& response, const char * api, const char * extraDeviceInfo = nullptr);
    std::string getCodeFromImap(const char * imapServer, int port, const char * mailBox, const char * fromName, const char* toEmail, const char * login_email, const char * login_password) const;
    std::string token() const;
    std::string deviceInfo() const;
    void pLog(int level, const char * TAG, const char * fmt, ...) const;
    static void pushLog2Server(const char* level, const char * TAG, const char * msg);

private:
    bool m_initState;
    bool m_unlockState;
    E_SUPPORTED_PLATFORM m_platform;
    std::string m_token;
    std::string m_deviceInfo;
    std::string m_dropBoxToken;
    std::string m_domain;
    std::list<std::string> m_existedPackagedList;
    std::vector<std::string> m_listKey;
    std::vector<std::string> m_listValue;
};



#endif //WEBAPI_H
