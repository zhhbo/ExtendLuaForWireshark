local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x000A] = function( buf, pkg, root, t, off, size )
  return dissectors.add( t, buf, 0,
    ">wTlvVer W",
    ">wErrorCode W",
    ">ErrorMsg wxline_string",
    );
end