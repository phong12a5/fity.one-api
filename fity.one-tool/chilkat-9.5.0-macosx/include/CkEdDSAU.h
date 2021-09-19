// CkEdDSAU.h: interface for the CkEdDSAU class.
//
//////////////////////////////////////////////////////////////////////

// This header is generated for Chilkat 9.5.0.88

#ifndef _CkEdDSAU_H
#define _CkEdDSAU_H
	
#include "chilkatDefs.h"

#include "CkString.h"
#include "CkUtf16Base.h"

class CkPrngU;
class CkPrivateKeyU;
class CkPublicKeyU;
class CkBinDataU;



#if !defined(__sun__) && !defined(__sun)
#pragma pack (push, 8)
#endif
 

// CLASS: CkEdDSAU
class CK_VISIBLE_PUBLIC CkEdDSAU  : public CkUtf16Base
{
	

	private:
	
	// Don't allow assignment or copying these objects.
	CkEdDSAU(const CkEdDSAU &);
	CkEdDSAU &operator=(const CkEdDSAU &);

    public:
	CkEdDSAU(void);
	virtual ~CkEdDSAU(void);

	

	static CkEdDSAU *createNew(void);
	

	
	void CK_VISIBLE_PRIVATE inject(void *impl);

	// May be called when finished with the object to free/dispose of any
	// internal resources held by the object. 
	void dispose(void);

	

	// BEGIN PUBLIC INTERFACE

	// ----------------------
	// Properties
	// ----------------------


	// ----------------------
	// Methods
	// ----------------------
	// Generates an Ed25519 key. privKey is an output argument. The generated key is
	// created in privKey.
	bool GenEd25519Key(CkPrngU &prng, CkPrivateKeyU &privKey);

	// Computes a shared secret given a private and public key. For example, Alice and
	// Bob can compute the identical shared secret by doing the following: Alice sends
	// Bob her public key, and Bob calls SharedSecretENC with his private key and
	// Alice's public key. Bob sends Alice his public key, and Alice calls
	// SharedSecretENC with her private key and Bob's public key. Both calls to
	// SharedSecretENC will produce the same result. The resulting bytes are returned
	// in encoded string form (hex, base64, etc) as specified by encoding.
	bool SharedSecretENC(CkPrivateKeyU &privkey, CkPublicKeyU &pubkey, const uint16_t *encoding, CkString &outStr);
	// Computes a shared secret given a private and public key. For example, Alice and
	// Bob can compute the identical shared secret by doing the following: Alice sends
	// Bob her public key, and Bob calls SharedSecretENC with his private key and
	// Alice's public key. Bob sends Alice his public key, and Alice calls
	// SharedSecretENC with her private key and Bob's public key. Both calls to
	// SharedSecretENC will produce the same result. The resulting bytes are returned
	// in encoded string form (hex, base64, etc) as specified by encoding.
	const uint16_t *sharedSecretENC(CkPrivateKeyU &privkey, CkPublicKeyU &pubkey, const uint16_t *encoding);

	// Signs the contents of bd and returns the signature according to encoding. The
	// encoding can be any encoding supported by Chilkat, such as "hex", "base64", etc.
	bool SignBdENC(CkBinDataU &bd, const uint16_t *encoding, CkPrivateKeyU &privkey, CkString &outStr);
	// Signs the contents of bd and returns the signature according to encoding. The
	// encoding can be any encoding supported by Chilkat, such as "hex", "base64", etc.
	const uint16_t *signBdENC(CkBinDataU &bd, const uint16_t *encoding, CkPrivateKeyU &privkey);

	// Verifies the signature against the contents of bd. The encodedSig is passed as an
	// encoded string (such as hex, base64, etc.) using the encoding specified by enocding.
	// The pubkey contains the Ed25519 public key used to verify.
	bool VerifyBdENC(CkBinDataU &bd, const uint16_t *encodedSig, const uint16_t *enocding, CkPublicKeyU &pubkey);





	// END PUBLIC INTERFACE


};
#if !defined(__sun__) && !defined(__sun)
#pragma pack (pop)
#endif


	
#endif
