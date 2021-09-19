// CkCsrU.h: interface for the CkCsrU class.
//
//////////////////////////////////////////////////////////////////////

// This header is generated for Chilkat 9.5.0.88

#ifndef _CkCsrU_H
#define _CkCsrU_H
	
#include "chilkatDefs.h"

#include "CkString.h"
#include "CkUtf16Base.h"

class CkPrivateKeyU;
class CkBinDataU;
class CkPublicKeyU;



#if !defined(__sun__) && !defined(__sun)
#pragma pack (push, 8)
#endif
 

// CLASS: CkCsrU
class CK_VISIBLE_PUBLIC CkCsrU  : public CkUtf16Base
{
	

	private:
	
	// Don't allow assignment or copying these objects.
	CkCsrU(const CkCsrU &);
	CkCsrU &operator=(const CkCsrU &);

    public:
	CkCsrU(void);
	virtual ~CkCsrU(void);

	

	static CkCsrU *createNew(void);
	

	
	void CK_VISIBLE_PRIVATE inject(void *impl);

	// May be called when finished with the object to free/dispose of any
	// internal resources held by the object. 
	void dispose(void);

	

	// BEGIN PUBLIC INTERFACE

	// ----------------------
	// Properties
	// ----------------------
	// The common name of the certificate to be generated. For SSL/TLS certificates,
	// this would be the domain name. For email certificates this would be the email
	// address.
	// 
	// It is the value for "CN" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.3")
	// 
	// This property is required for a CSR.
	// 
	void get_CommonName(CkString &str);
	// The common name of the certificate to be generated. For SSL/TLS certificates,
	// this would be the domain name. For email certificates this would be the email
	// address.
	// 
	// It is the value for "CN" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.3")
	// 
	// This property is required for a CSR.
	// 
	const uint16_t *commonName(void);
	// The common name of the certificate to be generated. For SSL/TLS certificates,
	// this would be the domain name. For email certificates this would be the email
	// address.
	// 
	// It is the value for "CN" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.3")
	// 
	// This property is required for a CSR.
	// 
	void put_CommonName(const uint16_t *newVal);

	// The company or organization name for the certificate to be generated.
	// 
	// It is the value for "O" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.10")
	// 
	// This property is optional. It may left empty.
	// 
	void get_Company(CkString &str);
	// The company or organization name for the certificate to be generated.
	// 
	// It is the value for "O" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.10")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *company(void);
	// The company or organization name for the certificate to be generated.
	// 
	// It is the value for "O" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.10")
	// 
	// This property is optional. It may left empty.
	// 
	void put_Company(const uint16_t *newVal);

	// The company division or organizational unit name for the certificate to be
	// generated.
	// 
	// It is the value for "OU" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.11")
	// 
	// This property is optional. It may left empty.
	// 
	void get_CompanyDivision(CkString &str);
	// The company division or organizational unit name for the certificate to be
	// generated.
	// 
	// It is the value for "OU" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.11")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *companyDivision(void);
	// The company division or organizational unit name for the certificate to be
	// generated.
	// 
	// It is the value for "OU" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.11")
	// 
	// This property is optional. It may left empty.
	// 
	void put_CompanyDivision(const uint16_t *newVal);

	// The two-letter uppercase country abbreviation, such as "US", for the certificate
	// to be generated.
	// 
	// It is the value for "C" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.6")
	// 
	// This property is optional. It may left empty.
	// 
	void get_Country(CkString &str);
	// The two-letter uppercase country abbreviation, such as "US", for the certificate
	// to be generated.
	// 
	// It is the value for "C" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.6")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *country(void);
	// The two-letter uppercase country abbreviation, such as "US", for the certificate
	// to be generated.
	// 
	// It is the value for "C" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.6")
	// 
	// This property is optional. It may left empty.
	// 
	void put_Country(const uint16_t *newVal);

	// The email address for the certificate to be generated.
	// 
	// It is the value for "E" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "1.2.840.113549.1.9.1")
	// 
	// This property is optional. It may left empty.
	// 
	void get_EmailAddress(CkString &str);
	// The email address for the certificate to be generated.
	// 
	// It is the value for "E" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "1.2.840.113549.1.9.1")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *emailAddress(void);
	// The email address for the certificate to be generated.
	// 
	// It is the value for "E" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "1.2.840.113549.1.9.1")
	// 
	// This property is optional. It may left empty.
	// 
	void put_EmailAddress(const uint16_t *newVal);

	// The hash algorithm to be used when creating the CSR. The default is SHA256. Can
	// be set to SHA1, SHA384, SHA256, or SHA512.
	void get_HashAlgorithm(CkString &str);
	// The hash algorithm to be used when creating the CSR. The default is SHA256. Can
	// be set to SHA1, SHA384, SHA256, or SHA512.
	const uint16_t *hashAlgorithm(void);
	// The hash algorithm to be used when creating the CSR. The default is SHA256. Can
	// be set to SHA1, SHA384, SHA256, or SHA512.
	void put_HashAlgorithm(const uint16_t *newVal);

	// The locality (city or town) name for the certificate to be generated.
	// 
	// It is the value for "L" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.7")
	// 
	// This property is optional. It may left empty.
	// 
	void get_Locality(CkString &str);
	// The locality (city or town) name for the certificate to be generated.
	// 
	// It is the value for "L" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.7")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *locality(void);
	// The locality (city or town) name for the certificate to be generated.
	// 
	// It is the value for "L" in the certificate's Subject's distinguished name (DN).
	// (This is the value for OID "2.5.4.7")
	// 
	// This property is optional. It may left empty.
	// 
	void put_Locality(const uint16_t *newVal);

	// If the private key is RSA and PssPadding equals true (RSASSA-PSS padding is
	// used for the RSA signature), then this property controls the MGF hash algorithm
	// used in the RSASSA-PSS padding. The default is "sha256". Can be set to "sha256",
	// "sha384", or "sha512".
	void get_MgfHashAlg(CkString &str);
	// If the private key is RSA and PssPadding equals true (RSASSA-PSS padding is
	// used for the RSA signature), then this property controls the MGF hash algorithm
	// used in the RSASSA-PSS padding. The default is "sha256". Can be set to "sha256",
	// "sha384", or "sha512".
	const uint16_t *mgfHashAlg(void);
	// If the private key is RSA and PssPadding equals true (RSASSA-PSS padding is
	// used for the RSA signature), then this property controls the MGF hash algorithm
	// used in the RSASSA-PSS padding. The default is "sha256". Can be set to "sha256",
	// "sha384", or "sha512".
	void put_MgfHashAlg(const uint16_t *newVal);

	// If _CKTRUE_, and if the private key is RSA, then uses RSASSA-PSS padding for the
	// signature.
	bool get_PssPadding(void);
	// If _CKTRUE_, and if the private key is RSA, then uses RSASSA-PSS padding for the
	// signature.
	void put_PssPadding(bool newVal);

	// The state or province for the certificate to be generated.
	// 
	// It is the value for "S" (or "ST") in the certificate's Subject's distinguished
	// name (DN). (This is the value for OID "2.5.4.8")
	// 
	// This property is optional. It may left empty.
	// 
	void get_State(CkString &str);
	// The state or province for the certificate to be generated.
	// 
	// It is the value for "S" (or "ST") in the certificate's Subject's distinguished
	// name (DN). (This is the value for OID "2.5.4.8")
	// 
	// This property is optional. It may left empty.
	// 
	const uint16_t *state(void);
	// The state or province for the certificate to be generated.
	// 
	// It is the value for "S" (or "ST") in the certificate's Subject's distinguished
	// name (DN). (This is the value for OID "2.5.4.8")
	// 
	// This property is optional. It may left empty.
	// 
	void put_State(const uint16_t *newVal);



	// ----------------------
	// Methods
	// ----------------------
	// Adds a SAN value (Subject Alternative Name) to the CSR to be generated. This
	// method can be called multiple times -- one per subject alternative name to be
	// added.
	// 
	// The sanType specifies the type of SAN, and can be one of the following strings:
	//     otherName
	//     rfc822Name
	//     dnsName
	//     x400Address
	//     directoryName
	//     ediPartyName
	//     uniformResourceIndicator
	//     IPAddress
	//     registeredID
	// 
	// The sanValue is the value. For example, if the sanType is "dsnName", the sanValue might be
	// "example.com". If the sanType is "IPAddress", then the sanValue might be
	// "69.12.122.63".
	// 
	bool AddSan(const uint16_t *sanType, const uint16_t *sanValue);

	// Generate a CSR and return the binary DER in csrData. The privKey can be an RSA or
	// ECDSA private key.
	bool GenCsrBd(CkPrivateKeyU &privKey, CkBinDataU &csrData);

	// Generate a CSR and return it as a PEM string. The privKey can be an RSA or ECDSA
	// private key.
	bool GenCsrPem(CkPrivateKeyU &privKey, CkString &outStr);
	// Generate a CSR and return it as a PEM string. The privKey can be an RSA or ECDSA
	// private key.
	const uint16_t *genCsrPem(CkPrivateKeyU &privKey);

	// Returns the CSR's public key in the pubkey.
	bool GetPublicKey(CkPublicKeyU &pubkey);

	// Gets a subject field by OID, such as "2.5.4.9".
	// Seehttp://www.alvestrand.no/objectid/2.5.4.html
	// <http://www.alvestrand.no/objectid/2.5.4.html> for OID values and meanings.
	bool GetSubjectField(const uint16_t *oid, CkString &outStr);
	// Gets a subject field by OID, such as "2.5.4.9".
	// Seehttp://www.alvestrand.no/objectid/2.5.4.html
	// <http://www.alvestrand.no/objectid/2.5.4.html> for OID values and meanings.
	const uint16_t *getSubjectField(const uint16_t *oid);
	// Gets a subject field by OID, such as "2.5.4.9".
	// Seehttp://www.alvestrand.no/objectid/2.5.4.html
	// <http://www.alvestrand.no/objectid/2.5.4.html> for OID values and meanings.
	const uint16_t *subjectField(const uint16_t *oid);

	// Loads this CSR object with a CSR PEM. All properties are set to the values found
	// within the CSR.
	bool LoadCsrPem(const uint16_t *csrPemStr);

	// Sets a subject field by OID, such as "2.5.4.9".
	// Seehttp://www.alvestrand.no/objectid/2.5.4.html
	// <http://www.alvestrand.no/objectid/2.5.4.html> for OID values and meanings.
	// 
	// The asnType can be "UTF8String", "IA5String", or "PrintableString". If you have no
	// specific requirement, or don't know, choose "UTF8String".
	// 
	bool SetSubjectField(const uint16_t *oid, const uint16_t *value, const uint16_t *asnType);

	// Verify the signature in the CSR. Return true if the signature is valid.
	bool VerifyCsr(void);





	// END PUBLIC INTERFACE


};
#if !defined(__sun__) && !defined(__sun)
#pragma pack (pop)
#endif


	
#endif
