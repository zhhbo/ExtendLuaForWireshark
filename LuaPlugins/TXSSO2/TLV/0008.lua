local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0008] = function( buf, pkg, root, t, off, size )
  return dissectors.add( t, buf, off,
    ">wTlvVer W",
    ">dwLocaleID D",
    ">wTimeZoneoffsetMin W"
    );
end