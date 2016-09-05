local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0004] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, off,
    ">wTlvVer W",
    ">bufAccount wxline_string"
    );
end