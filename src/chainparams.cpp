// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Unpay developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
    0xb32b80ef, 0x807f6aeb, 0x259dfa0a, 0xa2d16323, 0x6c3dd236,
    0xacf50584, 0x2ea2420a, 0x4e6db2c3, 0x8a80a95e, 0x340b8de5,
    0x253b153a, 0x2e69760f, 0xb2217edd, 0x68ec1783, 0x6c3dd125,
};

/*
$ python genesis.py -a X11 -z "Since May 2015, the Republic of Korea has been investigating an outbreak of MERS. It is the largest known outbreak of MERS outside the Arabian Peninsula."

04ffff001d01044c9953696e6365204d617920323031352c207468652052657075626c6963206f66204b6f72656120686173206265656e20696e7665737469676174696e6720616e206f7574627265616b206f66204d4552532e20497420697320746865206c617267657374206b6e6f776e206f7574627265616b206f66204d455253206f75747369646520746865204172616269616e2050656e696e73756c612e

algorithm: X11

merkle hash: b6df1d332acec3f426902d1ab6f981f9d69eeb07e5a78b8592f9ab9f3a1bbee0

pszTimestamp: Since May 2015, the Republic of Korea has been investigating an outbreak of MERS. It is the largest known outbreak of MERS outside the Arabian Peninsula.

pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
time: 1433994215
bits: 0x1e0ffff0
Searching for genesis hash..
11824.0 hash/s, estimate: 0.0 hgenesis hash found!
nonce: 6337833
genesis hash: 000003e14b723be4346c6ed7c61d46c7e6d6d83d4b1c3db38b2a38248d5a134c
*/

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        vAlertPubKey = ParseHex("048240a8748a80a286b270ba126705ced4f2ce5a7847b3610ea3c06513150dade2a8512ed5ea86320824683fc0818f0ac019214973e677acd1244f6d0571fc5103");
        nDefaultPort = 3338;
        nRPCPort = 3339;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);  // Unpay starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 210000;

        // Genesis block
        const char* pszTimestamp = "Since May 2015, the Republic of Korea has been investigating an outbreak of MERS. It is the largest known outbreak of MERS outside the Arabian Peninsula.";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;

        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1433994215;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 6337833;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000003e14b723be4346c6ed7c61d46c7e6d6d83d4b1c3db38b2a38248d5a134c"));
        assert(genesis.hashMerkleRoot == uint256("0xb6df1d332acec3f426902d1ab6f981f9d69eeb07e5a78b8592f9ab9f3a1bbee0"));

        vSeeds.push_back(CDNSSeedData("unpaybank.info", "dnsseed.unpaybank.info"));
        //vSeeds.push_back(CDNSSeedData("darkcoin.qa", "dnsseed.darkcoin.qa"));
        //vSeeds.push_back(CDNSSeedData("masternode.io", "dnsseed.masternode.io"));
        //vSeeds.push_back(CDNSSeedData("unpaypay.io", "dnsseed.unpaypay.io"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of( 76);                    // Unpay addresses start with 'X'
        base58Prefixes[SCRIPT_ADDRESS] = list_of( 16);                    // Unpay script addresses start with '7'
        base58Prefixes[SECRET_KEY] =     list_of(204);                    // Unpay private keys start with '7' or 'X'
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x02)(0xFE)(0x52)(0xF8); // Unpay BIP32 pubkeys start with 'drkv'
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x02)(0xFE)(0x52)(0xCC); // Unpay BIP32 prvkeys start with 'drkp'
        base58Prefixes[EXT_COIN_TYPE]  = list_of(0x80000005);             // Unpay BIP44 coin type is '5'

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xe2;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xff;

        vAlertPubKey = ParseHex("04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412");
        nDefaultPort = 13338;
        nRPCPort = 13339;
        strDataDir = "testnet3";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime    = 1433994530;
        genesis.nNonce   = 72436;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000890f1794585e882cbb9ec24760f2293fba338eb919232ff9c4f740267f4"));

        vFixedSeeds.clear();
        vSeeds.clear();
        /*vSeeds.push_back(CDNSSeedData("unpaypay.io", "testnet-seed.unpaypay.io"));
        vSeeds.push_back(CDNSSeedData("unpay.qa", "testnet-seed.unpay.qa"));
        *///legacy seeders
        // vSeeds.push_back(CDNSSeedData("darkcoin.io",  "testnet-seed.darkcoin.io"));
        // vSeeds.push_back(CDNSSeedData("darkcoin.qa", "testnet-seed.darkcoin.qa"));
        // vSeeds.push_back(CDNSSeedData("masternode.io", "test.dnsseed.masternode.io"));
        vSeeds.push_back(CDNSSeedData("unpaybank.info",  "testnet-seed.unpaybank.info"));
 
        base58Prefixes[PUBKEY_ADDRESS] = list_of(139);                    // Testnet unpay addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = list_of( 19);                    // Testnet unpay script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY]     = list_of(239);                    // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x3a)(0x80)(0x61)(0xa0); // Testnet unpay BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x3a)(0x80)(0x58)(0x37); // Testnet unpay BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_COIN_TYPE]  = list_of(0x80000001);             // Testnet unpay BIP44 coin type is '5' (All coin's testnet default)
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        
        genesis.nTime    = 1433994930;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 201766;

        nDefaultPort = 13338;
        strDataDir = "regtest";

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000fab14b23407944729f8f69ba3b1633eaef0d9c313aa5f19dcd20a10334f"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
