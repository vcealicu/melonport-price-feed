pragma solidity ^0.4.8;

import "github.com/melonproject/protocol/contracts/datafeeds/PriceFeedProtocol.sol";
import "github.com/melonproject/protocol/contracts/assets/Asset.sol";
import "github.com/melonproject/protocol/contracts/dependencies/ERC20.sol";
import "github.com/melonproject/protocol/contracts/dependencies/SafeMath.sol";
import "github.com/melonproject/protocol/contracts/dependencies/Owned.sol";
import "github.com/oraclize/ethereum-api/oraclizeAPI.sol";
import "github.com/Arachnid/solidity-stringutils/strings.sol";

/// @title Price Feed Contract
/// @author Melonport AG <team@melonport.com>
/// @notice Routes external data to smart contracts
contract JSON_Decoder {
  using strings for *;

  function JSONpath_raw(string _json, string _path) constant returns(string) {
    uint depth;

    var s = _json.toSlice();
    var argSliced = _path.toSlice();

    (argSliced, s, depth) = nestedPath(argSliced, s);

    var key = makeKey(argSliced);

    if (s.contains(key)) {
      var pre = s.split(key);
      depth += depthCheck(pre);

      return getElement(s, depth);
    } else {
      //Assumes if the key above was not found
      //that key is in fact an array index
      //may fail if a key uses a numerical value
      //if becomes issue, could use ...data.[0] or the like

      uint x = parseInt(key.toString(), 0);

      if (s.startsWith(' ['.toSlice()) || s.startsWith('['.toSlice())) {
        //remove opening/closing array brackets
        s = s.split(']'.toSlice());
        s = s.rsplit('['.toSlice());

        //split into string array
        var delim = ",".toSlice();

        //handles single-element array
        if (s.count(delim) == 0 && x == 0)
          return s.toString();

        //handle multi-element array
        var parts = new string[](s.count(delim) + 1);

        for (uint i = 0; i < parts.length; i++) {
          parts[i] = s.split(delim).toString();
        }
      }
      return parts[x];
    }
  }

  // strips any double quotes, escaped quotes must be handled manually
  function JSONpath_string(string _json, string _path) constant returns(string _r) {
    _r = JSONpath_raw(_json, _path);

    var s = _r.toSlice();
    var delim = '"'.toSlice();

    if (s.contains(delim)) {
      var parts = new strings.slice[](s.count(delim));
      var resultSlice = ''.toSlice();
      for (uint i = 0; i < parts.length; i++) {
          parts[i] = s.split(delim);
      }

      return ''.toSlice().join(parts);
    }

  }

  function JSONpath_int(string _json, string _path, uint _decimals) constant returns(uint) {
      return parseInt(JSONpath_string(_json, _path), _decimals);
  }

  function nestedPath(strings.slice _path, strings.slice _s)
  private
  returns(strings.slice, strings.slice, uint) {

    var delim = '.'.toSlice();
    uint depth = 0;

    while (_path.contains(delim)) {
      var a = _path.split(delim);
      var pre = _s.split(makeKey(a));

      depthCheck(pre);
      depth++;
    }
    return (_path, _s, depth);
  }

  function makeKey(strings.slice _key)
  private
  returns(strings.slice) {

    _key = '"'.toSlice().concat(_key).toSlice();

    return _key.concat('":'.toSlice()).toSlice();
  }

  function getElement(strings.slice _s, uint _depth)
  private
  returns(string) {

    var endCurlySlice = '}'.toSlice();
    var spaceSlice = ' '.toSlice();
    var quoteSlice = '"'.toSlice();

    //may be unneeded with latest revision
    while (_depth > 0) {
      _s.rsplit(endCurlySlice);
      _depth--;
    }

    //pre-format by taking out extra spaces if applicable
    while (_s.startsWith(spaceSlice))
      _s.split(spaceSlice);

    if (_s.startsWith(quoteSlice)) {
      //return "true";
      _s.split(quoteSlice);
      _s = _s.split(quoteSlice);
    } else if (_s.startsWith('['.toSlice())) {
      //For keys with array value
      var endSquareSlice = ']'.toSlice();

      _s = _s.split(endSquareSlice);
      _s = _s.concat(endSquareSlice).toSlice();
    } else if (_s.startsWith('{'.toSlice())) {
      //For keys referencing objects

      //Could potentially fix duplicate issue on
      //initial conditional if they arise
      //but would make more expensive

      var parts = new string[](_s.count(endCurlySlice) + 1);
      for (uint i = 0; i < parts.length; i++) {
        parts[i] = _s.split(endCurlySlice).concat(endCurlySlice);
      }

      _s = parts[0].toSlice();
      i = 0;

      while (_s.count(endCurlySlice) != _s.count('{'.toSlice()) && i < parts.length) {
        i++;
        _s = _s.concat(parts[i].toSlice()).toSlice();
      }

    } else {
      //For other cases, namely just a number/int
      _s = _s.split(','.toSlice());
      _s = _s.split(endCurlySlice);
    }

    return _s.toString();
  }

  //ensures depth is in proper increments
  function depthCheck(strings.slice _pre)
  private
  returns(uint depth) {
    depth = _pre.count('{'.toSlice());
    if (depth != _pre.count('}'.toSlice()) + 1)
      throw;

    depth = 1;
  }

  /* Copyright (C) 2016 Thomas Bertani - Oraclize */
  function parseInt(string _a, uint _b) internal returns(uint) {
    bytes memory bresult = bytes(_a);
    uint mint = 0;
    bool decimals = false;
    for (uint i = 0; i < bresult.length; i++) {
      if ((bresult[i] >= 48) && (bresult[i] <= 57)) {
        if (decimals) {
          if (_b == 0) break;
          else _b--;
        }
        mint *= 10;
        mint += uint(bresult[i]) - 48;
      } else if (bresult[i] == 46) decimals = true;
    }
    if (_b > 0) mint *= 10**_b;
    return mint;
  }
}

contract b64 {

    function b64decode(bytes s) internal returns (bytes) {
        byte v1;
        byte v2;
        byte v3;
        byte v4;

        //bytes memory s = bytes(_s);
        uint length = s.length;
        bytes memory result = new bytes(length);

        uint index;

        bytes memory BASE64_DECODE_CHAR = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e003e003f3435363738393a3b3c3d00000000000000000102030405060708090a0b0c0d0e0f10111213141516171819000000003f001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233";
        //MAP[chr]
        if (sha3(s[length - 2]) == sha3('=')) {
            length -= 2;
        } else if (sha3(s[length - 1]) == sha3('=')) {
            length -= 1;
        }

        uint count = length >> 2 << 2;

        for (uint i = 0; i < count;) {
            v1 = BASE64_DECODE_CHAR[uint(s[i++])];
            v2 = BASE64_DECODE_CHAR[uint(s[i++])];
            v3 = BASE64_DECODE_CHAR[uint(s[i++])];
            v4 = BASE64_DECODE_CHAR[uint(s[i++])];


            result[index++] = (v1 << 2 | v2 >> 4) & 255;
            result[index++] = (v2 << 4 | v3 >> 2) & 255;
            result[index++] = (v3 << 6 | v4) & 255;
        }

       if (length - count == 2) {
            v1 = BASE64_DECODE_CHAR[uint(s[i++])];
            v2 = BASE64_DECODE_CHAR[uint(s[i++])];
            result[index++] = (v1 << 2 | v2 >> 4) & 255;
        }
        else if (length - count == 3) {
            v1 = BASE64_DECODE_CHAR[uint(s[i++])];
            v2 = BASE64_DECODE_CHAR[uint(s[i++])];
            v3 = BASE64_DECODE_CHAR[uint(s[i++])];

            result[index++] = (v1 << 2 | v2 >> 4) & 255;
            result[index++] = (v2 << 4 | v3 >> 2) & 255;
        }

        // set to correct length
        assembly {
            mstore(result, index)
        }

        //debug(result);
        //res = result;
        return result;
    }
}

contract ECVerify {
    // Duplicate Solidity's ecrecover, but catching the CALL return value
    function safer_ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal returns (bool, address) {
        // We do our own memory management here. Solidity uses memory offset
        // 0x40 to store the current end of memory. We write past it (as
        // writes are memory extensions), but don't update the offset so
        // Solidity will reuse it. The memory used here is only needed for
        // this context.

        // FIXME: inline assembly can't access return values
        bool ret;
        address addr;

        assembly {
            let size := mload(0x40)
            mstore(size, hash)
            mstore(add(size, 32), v)
            mstore(add(size, 64), r)
            mstore(add(size, 96), s)

            // NOTE: we can reuse the request memory because we deal with
            //       the return code
            ret := call(3000, 1, 0, size, 128, size, 32)
            addr := mload(size)
        }

        return (ret, addr);
    }

    function ecrecovery(bytes32 hash, bytes sig) internal returns (bool, address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (sig.length != 65)
          return (false, 0);

        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))

            // Here we are loading the last 32 bytes. We exploit the fact that
            // 'mload' will pad with zeroes if we overread.
            // There is no 'mload8' to do this, but that would be nicer.
            v := byte(0, mload(add(sig, 96)))

            // Alternative solution:
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            // v := and(mload(add(sig, 65)), 255)
        }

        // albeit non-transactional signatures are not specified by the YP, one would expect it
        // to match the YP range of [27, 28]
        //
        // geth uses [0, 1] and some clients have followed. This might change, see:
        //  https://github.com/ethereum/go-ethereum/issues/2053
        if (v < 27)
          v += 27;

        if (v != 27 && v != 28)
            return (false, 0);

        return safer_ecrecover(hash, v, r, s);
    }

}

contract PriceFeed is usingOraclize, ECVerify, b64, JSON_Decoder, PriceFeedProtocol, SafeMath, Owned {
    using strings for *;

    // TYPES

    struct Data {
        uint timestamp; // Timestamp of last price update of this asset
        uint price; // Price of asset quoted against `quoteAsset` times ten to the power of {decimals of this asset}
    }

    struct AssetInfo {
        address assetAddress;
        string assetTicker;
    }

    // FIELDS

    // Constant fields
    // Token addresses on Kovan
    address public constant ETHER_TOKEN = 0x7506c7BfED179254265d443856eF9bda19221cD7;
    address public constant MELON_TOKEN = 0x4dffea52b0b4b48c71385ae25de41ce6ad0dd5a7;
    address public constant BITCOIN_TOKEN = 0x9E4C56a633DD64a2662bdfA69dE4FDE33Ce01bdd;
    address public constant EURO_TOKEN = 0xF61b8003637E5D5dbB9ca8d799AB54E5082CbdBc;
    address public constant REP_TOKEN = 0xC151b622fDeD233111155Ec273BFAf2882f13703;

    // Fields that are only changed in constructor
    /// Note: By definition the price of the quote asset against itself (quote asset) is always equals one
    address quoteAsset; // Is the quote asset of a portfolio against which all other assets are priced against
    // Fields that can be changed by functions
    uint frequency = 300; // Frequency of updates in seconds
    uint validity = 600; // Time in seconds data is considered valid
    uint gasLimit = 350000;
    uint public numAssets = 0;
    bytes ds_pubkey;

    mapping(uint => AssetInfo) public assetsIndex;
    mapping (address => Data) data; // Address of fungible => price of fungible

    // EVENTS

    event PriceUpdated(address indexed ofAsset, uint atTimestamp, uint ofPrice);

    // ORACLIZE DATA-STRUCTURES

    bool continuousDelivery;
    string oraclizeQuery;

    // MODIFIERS

   modifier msg_value_at_least(uint x) {
        assert(msg.value >= x);
        _;
    }

    modifier data_initialised(address ofAsset) {
        assert(data[ofAsset].timestamp > 0);
        _;
    }

    modifier data_still_valid(address ofAsset) {
        assert(now - data[ofAsset].timestamp <= validity);
        _;
    }

    modifier arrays_equal(address[] x, uint[] y) {
        assert(x.length == y.length);
        _;
    }

    modifier only_oraclize {
        if (msg.sender != oraclize_cbAddress()) throw;
        _;
    }

    // CONSTANT METHODS

    function getQuoteAsset() constant returns (address) { return quoteAsset; }
    function getFrequency() constant returns (uint) { return frequency; }
    function getValidity() constant returns (uint) { return validity; }

    // Pre: Checks for initialisation and inactivity
    // Post: Price of asset, where last updated not longer than `validity` seconds ago
    function getPrice(address ofAsset)
        constant
        data_initialised(ofAsset)
        data_still_valid(ofAsset)
        returns (uint)

    {
        return data[ofAsset].price;
    }

    function getPublicKey()
        constant
        returns (bytes)
    {
        return ds_pubkey;
    }

    // Pre: Checks for initialisation and inactivity
    // Post: Timestamp and price of asset, where last updated not longer than `validity` seconds ago
    function getData(address ofAsset)
        constant
        data_initialised(ofAsset)
        data_still_valid(ofAsset)
        returns (uint, uint)
    {
        return (data[ofAsset].timestamp, data[ofAsset].price);
    }

    // NON-CONSTANT METHODS

    function PriceFeed() payable {
        oraclize_setProof(240);
        quoteAsset = ETHER_TOKEN; // Is the quote asset of a portfolio against which all other assets are priced against
        /* Note:
         *  Prices shold be quoted in quoteAsset
         *  1) ETH/MLN
         *  2) BTC/ETH -> ETH/BTC
         *  3) EUR/ETH -> ETH/EUR
         *  4) ETH/REP
         */
        setQuery("https://min-api.cryptocompare.com/data/price?fsym=ETH&tsyms=BTC,EUR,MLN,REP&sign=true");
        ds_pubkey = hex"a0f4f688350018ad1b9785991c0bde5f704b005dc79972b114dbed4a615a983710bfc647ebe5a320daa28771dce6a2d104f5efa2e4a85ba3760b76d46f8571ca";
        enableContinuousDelivery();
        oraclize_query('URL', oraclizeQuery, 500000);
    }

    function () payable {}

    // NON-CONSTANT METHODS

     function nativeProof_verify(string result, bytes proof, bytes pubkey) private returns (bool){
        uint sig_len = uint(proof[1]);
        bytes memory sig = new bytes(sig_len);
        sig = copyBytes(proof, 2, sig_len, sig, 0);
        uint headers_len = uint(proof[2+sig_len])*256 + uint(proof[2+sig_len+1]);
        bytes memory headers = new bytes(headers_len);
        headers = copyBytes(proof, 4+sig_len, headers_len, headers, 0);
        bytes memory digest = new bytes(headers_len-52); //len("digest: SHA-256=")=16
        digest = copyBytes(headers, 52, headers_len-52, digest, 0);
        bool digestok = (sha3(sha256(result)) == sha3(b64decode(digest)));
        if (!digestok) return false;
        bool sigok;
        address signer;
        (sigok, signer) = ecrecovery(sha256(headers), sig);
        return (signer == address(sha3(pubkey)));
    }

    function copyBytes(bytes from, uint fromOffset, uint length, bytes to, uint toOffset) internal returns (bytes) {
        uint minLength = length + toOffset;

        if (to.length < minLength) {
            // Buffer too small
            throw; // Should be a better way?
        }

        // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
        uint i = 32 + fromOffset;
        uint j = 32 + toOffset;

        while (i < (32 + fromOffset + length)) {
            assembly {
                let tmp := mload(add(from, i))
                mstore(add(to, j), tmp)
            }
            i += 32;
            j += 32;
        }

        return to;
    }

    function __callback(bytes32 oraclizeId, string result, bytes proof) only_oraclize {
        // Update prices only if native proof is verified
        if (nativeProof_verify(result, proof, ds_pubkey)) {
            for (uint i=1; i <= numAssets; i++) {
                AssetInfo thisAsset = assetsIndex[i];
                setPriceOf(result, thisAsset.assetTicker, thisAsset.assetAddress);
            }
        }

        if (continuousDelivery) {
           updatePriceOraclize();
        }
    }

    function setPriceOf(string result, string ticker, address assetAddress) internal {
        Asset currentAsset = Asset(assetAddress);
        uint decimals = currentAsset.getDecimals();
        uint price = parseInt(JSONpath_string(result, ticker), decimals);
        data[assetAddress] = Data(now, price);
        PriceUpdated(assetAddress, now, price);
    }


    function setQuery(string query) only_owner {
        oraclizeQuery = query;
    }

    function updateKey(bytes _pubkey) only_owner {
        ds_pubkey = _pubkey;
    }

    function enableContinuousDelivery() only_owner {
        continuousDelivery = true;
    }

    function disableContinuousDelivery() only_owner {
        delete continuousDelivery;
    }

    function setGasLimit(uint _newGasLimit) only_owner {
        gasLimit = _newGasLimit;
    }

    function updatePriceOraclize()
        payable {
        bytes32 oraclizeId = oraclize_query(frequency,'URL', oraclizeQuery, gasLimit);
    }

    function setFrequency(uint newFrequency) only_owner {
        if (frequency > validity) throw;
        frequency = newFrequency;
    }

    function setValidity(uint _validity) only_owner {
        validity = _validity;
    }

    function addAsset(string _ticker, address _newAsset) only_owner {
        numAssets += 1;
        assetsIndex[numAssets] = AssetInfo(_newAsset, _ticker);
    }

    function rmAsset(uint _index) only_owner {
        delete assetsIndex[_index];
        numAssets -= 1;
    }

}
