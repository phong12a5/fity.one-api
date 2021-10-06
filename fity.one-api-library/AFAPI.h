#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, E_SUPPORTED_PLATFORM) {
    PLATFORM_UNKNOWN = 0,
    PLATFORM_F_CARE,
    PLATFORM_F_SYSTEM,
    PLATFORM_F_ANDROID,
    PLATFORM_F_ANDROID_WEBVIEW,
    PLATFORM_F_IOS,
    PLATFORM_F_IOS_WEBVIEW
};

@interface AFAPI: NSObject

typedef struct device_info{
    NSString* device_id;
    NSString* app_version_name;
} DEVICE_INFO;

+ (instancetype)instance;

+ (NSString*) version;

    /**
     * @brief AFAPI must be initialized before using
     *
     * @param token
     * @param deviceInfo -> example:
    /// code
    DEVICE_INFO deviceInfo;
    deviceInfo.device_id = (char*)"123456789";
    deviceInfo.app_version_name = (char*)"0.0.1";
    /// code
     * @return true
     * @return false
     */
-(BOOL) initWebAPIs:(NSString*) token device_info:(DEVICE_INFO) deviceInfo;

    // Config APIs
    /**
     * @brief register this device to server, webapi is availble when this device is approved from website
     *
     * @param extraDeviceInfo: at present, this param is unused
     * @return std::string
     */
-(NSDictionary*) upsertDevice: (NSDictionary *) extraDeviceInfo;
    /**
     * @brief update status of this device to server
     * NOTE: at present, this api is just for fun
     * @param extraDeviceInfo: at present, this param is unused
     * @return std::string
     */
    // std::string updateDeviceInfo(const char * extraDeviceInfo = nullptr);
    // /**
    //  * @brief Get the Configuration of this device from server
    //  *
    //  * @return std::string
    //  */
    // std::string getConfig();
    // /**
    //  * @brief Get the Clone live from server
    //  *
    //  * @return std::string
    //  */
    // std::string getClone();
    // /**
    //  * @brief Get the full Clone Info
    //  *
    //  * @param cloneJsonPath: example: cloneJsonPath: {
    //         "alive_status": "stored",
    //         "appname": "facebook",
    //         "id": "614ca178658a2ec8c04e67ae",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //  * @return std::string
    //  */
    // std::string getCloneInfo(const char * cloneJsonPath);

    // /**
    //  * @brief Get the Stored Clones in this device
    //  *
    //  * @return std::string
    //  */
    // std::string getStoredClones();
    // /**
    //  * @brief update clone info to server
    //  *
    //  * @param action
    //  * @param cloneJsonPath: example: cloneJsonPath: {
    //         "alive_status": "stored",
    //         "appname": "facebook",
    //         "id": "614ca178658a2ec8c04e67ae",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //  * @return std::string
    //  */
    // std::string updateClone(const char * action, const char * cloneJsonPath);

    // /**
    //  * @brief Get the Jasmine Definitions object
    //  * @note this api is only for f_phone
    //  * @return std::string
    //  */
    // std::string getJasmineDefinitions();

    // /**
    //  * @brief submit clone ids which will open:
    //  * @example: stored clones:
    //  *  clone1_JsonPath: {
    //         "alive_status": "live",
    //         "appname": "facebook",
    //         "id": "614ca178658a2ec8c04e67ae",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //     clone2_JsonPath: {
    //         "alive_status": "live",
    //         "appname": "facebook",
    //         "id": "32483hfuty9823798hd234556345",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //  * @example: submitActiveClones("[614ca178658a2ec8c04e67ae, 32483hfuty9823798hd234556345]");
    //  * @param activeClones
    //  * @return std::string
    //  */
    // std::string submitActiveClones(const char * activeClones);

    // // Get actions APIs
    // /**
    //  * @brief obtain actions for clone_id from server
    //  * @example:
    //     cloneJsonPath: {
    //         "alive_status": "live",
    //         "appname": "facebook",
    //         "id": "614ca178658a2ec8c04e67ae",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //  * @param clone_id: example: 614ca178658a2ec8c04e67ae
    //  * @return std::string
    //  */
    // std::string doAction(const char * clone_id);

    // // Submit Result APIs
    // /**
    //  * @brief submit task status to server
    //  * @example:
    //     cloneJsonPath: {
    //         "alive_status": "live",
    //         "appname": "facebook",
    //         "id": "614ca178658a2ec8c04e67ae",
    //         "uid": "1000485734857394",
    //         "password": "phong1994"
    //     }
    //  * @param clone_id : example: 614ca178658a2ec8c04e67ae
    //  * @param dataJsonPath: example: {"service_code":"XXXXX", "action":"FeedLike"}
    //  * @return std::string
    //  */
    // std::string doResult(const char * clone_id, const char * dataJsonPath);

    // // Dropbox APIs
    // /**
    //  * @brief download file from dropbox
    //  *
    //  * @param pathFile : cloud file path
    //  * @param savePath : local file path
    //  * @return true if succeed | false if failed
    //  */
    // bool downloadFileFromDropbox(const char* pathFile, const char* savePath);
    // /**
    //  * @brief Get the Folder Content in dropbox
    //  *
    //  * @param folderPath
    //  * @return std::string
    //  */
    // std::string getFolderContent(const char * folderPath);

    // // Hotmail APIs
    // /**
    //  * @brief Get the Hotmail object
    //  *
    //  * @return std::string
    //  */
    // std::string getHotmail();

    // /**
    //  * @brief Check hotmail live/died
    //  *
    //  * @param email
    //  * @param password
    //  * @return true
    //  * @return false
    //  */
    // bool        checkLoginHotmail(std::string& email, std::string& password) const;

    // /**
    //  * @brief Get the Facebook Code From CGB Domain Mail
    //  *
    //  * @param email
    //  * @return std::string
    //  */
    // std::string getFacebookCodeFromCGBDomainMail(const char * email) const;
    // /**
    //  * @brief Get the Tiktok Code From CGB Domain Mail
    //  *
    //  * @param email
    //  * @return std::string
    //  */
    // std::string getTiktokCodeFromCGBDomainMail(const char * email) const;

    // /**
    //  * @brief Get the Facebook Code From Hotmail
    //  *
    //  * @param email
    //  * @param password
    //  * @return std::string
    //  */
    // std::string getFacebookCodeFromHotmail(const char * email, const char * password) const;

    // /**
    //  * @brief Get the Tiktok Code From Hotmail
    //  *
    //  * @param email
    //  * @param password
    //  * @return std::string
    //  */
    // std::string getTiktokCodeFromHotmail(const char * email, const char * password) const;

    // //util
    // /**
    //  * @brief obtain tOPT
    //  *
    //  * @param secretkey
    //  * @return std::string
    //  */
    // static std::string tOTP(const char * secretkey);

    // /**
    //  * @brief download file by quickly GET request
    //  *
    //  * @param url
    //  * @param savedPath
    //  * @return true
    //  * @return false
    //  */
    // static bool downloadFile(std::string& url, const std::string& savedPath);


    // bool initState() const;
    // void setInitState(bool state);
    // bool getDropboxToken(std::string &dropboxToken);
    // std::string getDomain();
    // std::string getUrlByAPI(std::string api);
    // static const char * getKey();
    // static const char * getIv();
    // static bool unlockChilkat();
    // bool encryptCloneInfo(std::string& cloneInfo);
    // bool decryptCloneInfo(std::string& cloneInfo);
    // bool sendRequest(const char * caller, CkJsonObject& data, CkJsonObject& response, const char * api, const char * extraDeviceInfo = nullptr);
    // std::string getCodeFromImap(const char * imapServer, int port, const char * mailBox, const char * fromName, const char* toEmail, const char * login_email, const char * login_password) const;
    // std::string token() const;
    // DEVICE_INFO deviceInfo() const;
    // void pLog(int level, const char * TAG, const char * fmt, ...) const;
    // static void pushLog2Server(const char* level, const char * TAG, const char * msg);

@end
