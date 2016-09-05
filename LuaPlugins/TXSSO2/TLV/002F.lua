local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x002F] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0,
    ">wTlvVer W",
    ">bufControl"
    );
end