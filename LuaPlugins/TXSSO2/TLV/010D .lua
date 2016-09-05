local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x010D] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0,
    ">wTlvVer W",
    ">bufSigLastLoginInfo wxline_bytes"
    );
end